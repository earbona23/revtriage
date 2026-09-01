#!/usr/bin/env python3
"""Mutation testing: are the tests load-bearing, or are they decoration?

A green suite proves the tests ran. It does not prove they would notice if the analyser
were wrong. This harness breaks revtriage on purpose -- one small, plausible edit at a
time, in the places where being wrong would be expensive -- and demands the suite go red.
A mutant nothing kills is a line of code nothing is checking.

THE TRAP THIS HARNESS EXISTS TO AVOID: a mutation that never got applied looks *exactly*
like a mutant that survived. The suite passes either way, and the flattering reading is
"killed". So every mutation asserts its target text is present before the edit and that
the bytes on disk actually moved after it. A mutation that cannot be applied is reported
as an ERROR -- never as a kill, never as a survivor.

    python3 scripts/mutation_test.py             # every mutant
    python3 scripts/mutation_test.py --list
    python3 scripts/mutation_test.py --only scoring
"""

from __future__ import annotations

import argparse
import hashlib
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "revtriage"


@dataclass(frozen=True)
class Mutant:
    name: str
    path: Path
    old: str
    new: str
    breaks: str  # the damage this defect would do in the field


MUTANTS: list[Mutant] = [
    # -- the score ------------------------------------------------------------------
    Mutant(
        "scoring/cap-becomes-a-floor",
        SRC / "scoring.py",
        "contribution = min(node.weight, ceiling)",
        "contribution = max(node.weight, ceiling)",
        "one behaviour detected twenty ways outscores three genuinely distinct ones",
    ),
    Mutant(
        "scoring/verdict-band-boundary",
        SRC / "scoring.py",
        "if value >= threshold:",
        "if value > threshold:",
        "a file scoring exactly 60 is reported one band below malicious",
    ),
    Mutant(
        "scoring/lethal-bonus-dropped",
        SRC / "scoring.py",
        "        total += edge.bonus",
        "        total += 0",
        "persistence plus C2 stops meaning more than the two apart -- an implant scores as two scripts",
    ),
    Mutant(
        "scoring/clamp-is-not-a-clamp",
        SRC / "scoring.py",
        "value = max(SCORE_MIN, min(total, SCORE_MAX))",
        "value = total",
        "the report prints a score above 100 and the progress bar overruns",
    ),
    # -- the capability graph -------------------------------------------------------
    Mutant(
        "graph/weight-counts-every-match",
        SRC / "capabilities/graph.py",
        "        best: dict[str, int] = {}\n        for match in self.matches:\n            best[match.rule_id] = match.weight\n        return sum(best.values())",
        "        return sum(match.weight for match in self.matches)",
        "one rule firing in three layers counts as three times the evidence; every string-based detection silently doubles",
    ),
    Mutant(
        "graph/edge-needs-only-one-side",
        SRC / "capabilities/graph.py",
        "if first in present and second in present:",
        "if first in present or second in present:",
        "a lethal-combination bonus is awarded for half a combination",
    ),
    # -- the deobfuscation keep-gate ------------------------------------------------
    Mutant(
        "deob/keep-threshold-boundary",
        SRC / "deobfuscate/score.py",
        "return interest(data) >= threshold",
        "return interest(data) > threshold",
        "a decode carrying exactly one marker -- the common case -- is thrown away",
    ),
    Mutant(
        "deob/compressed-check-is-a-rubber-stamp",
        SRC / "deobfuscate/score.py",
        "            return len(zlib.decompressobj(31).decompress(data, 4096)) > 0",
        "            return True",
        "any two bytes that look like a gzip header score 40, so noise becomes a layer",
    ),
    Mutant(
        "xor/key-zero-is-reported",
        SRC / "deobfuscate/xor.py",
        "    for key in range(1, 256):\n        for anchor in anchors:",
        "    for key in range(0, 256):\n        for anchor in anchors:",
        "every file 'decodes' with key 0 -- an identity transform reported as a recovered key",
    ),
    # -- the free/PRO boundary ------------------------------------------------------
    Mutant(
        "analyze/pro-rules-move-the-verdict",
        SRC / "analyze.py",
        "        matches.extend(extended_matches)",
        "        matches.extend(extended_matches)\n        score = compute_score(matches)",
        "a PRO licence changes a free-tier verdict, which is the one thing the tier promise forbids",
    ),
    Mutant(
        "analyze/sandbox-claims-it-ran",
        SRC / "analyze.py",
        '            FEATURE_SANDBOX, "skipped",',
        '            FEATURE_SANDBOX, "ok",',
        "a feature that never ran reports as ran-and-found-nothing, which is how a gap becomes an all-clear",
    ),
    # -- the licence ----------------------------------------------------------------
    Mutant(
        "license/signature-not-checked",
        SRC / "license/verify.py",
        "    if not keys.verify(public, message, signature):",
        "    if False:",
        "any self-made token unlocks PRO",
    ),
    Mutant(
        "license/expiry-ignored",
        SRC / "license/verify.py",
        "        if now > expiry:",
        "        if False:",
        "an expired licence keeps working forever",
    ),
    # -- the STIX contract ----------------------------------------------------------
    Mutant(
        "stix/validator-is-a-rubber-stamp",
        SRC / "report/stix.py",
        "        if not _ID_RE.match(obj_id):",
        "        if False:",
        "a malformed bundle validates here and is rejected by the platform it is fed to",
    ),
    # -- the structural guarantees ----------------------------------------------------
    Mutant(
        "guarantees/a-network-module-sneaks-in",
        SRC / "analyze.py",
        "from . import __version__, iocs",
        "import socket  # a 'harmless' enrichment\nfrom . import __version__, iocs",
        "the offline promise is broken and nothing notices: a sample can learn it is being analysed",
    ),
    Mutant(
        "guarantees/a-decoded-layer-becomes-code",
        SRC / "analyze.py",
        "    indicators = iocs.extract(texts)",
        "    indicators = iocs.extract(texts)\n    eval(compile('0', '<x>', 'eval'))",
        "the one thing this tool must never do -- turn sample-derived data into behaviour",
    ),
    # -- indicator safety -----------------------------------------------------------
    Mutant(
        "iocs/defang-does-nothing",
        SRC / "iocs.py",
        '    return value.replace("http", "hxxp").replace("ftp", "fxp").translate(_DEFANG)',
        "    return value",
        "a live malware URL is printed clickable into a ticket, a chat and someone's browser",
    ),
]



def purge_bytecode() -> int:
    """Delete every __pycache__ under the project before measuring anything.

    Restoring a mutant rewrites the file with content of the SAME LENGTH. CPython
    invalidates a .pyc by comparing the source's (mtime, size), both of which can be
    unchanged if the restore lands in the same clock second as the compile -- so the
    interpreter reuses bytecode compiled from the MUTATED source. That is a false kill:
    the defect is still executing while the tree on disk looks clean. Subprocesses run
    with -B and PYTHONDONTWRITEBYTECODE so no new cache is created; this clears whatever
    was there before.
    """
    removed = 0
    for cache in ROOT.rglob("__pycache__"):
        if ".venv" in cache.parts or ".git" in cache.parts:
            continue
        for item in sorted(cache.rglob("*"), reverse=True):
            item.unlink() if item.is_file() else item.rmdir()
        cache.rmdir()
        removed += 1
    return removed


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


_IN_FLIGHT: dict[Path, str] = {}


def _restore_and_die(signum, _frame):  # pragma: no cover - only on SIGTERM/SIGINT
    """A killed harness must not leave a mutant behind.

    `timeout` sends SIGTERM, and CPython's default handler exits WITHOUT running
    `finally`. Without this, a run that hits its limit leaves the source mutated, and the
    next green suite is green for the wrong reason.
    """
    for path, original in _IN_FLIGHT.items():
        path.write_text(original, encoding="utf-8")
    print(f"\ninterrupted by signal {signum}; restored {len(_IN_FLIGHT)} file(s)", file=sys.stderr)
    sys.exit(130)


SUITE_TIMEOUT_S = 300
"""A mutant may not fail the suite -- it may hang it.

Without a limit, "still running" is indistinguishable from "survived". A run that exceeds
this is counted as killed-by-hang and labelled as such, because a suite that never
finishes has certainly not passed.
"""


def _suite_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_suite() -> tuple[bool, str]:
    """Returns (mutant_survived, how) where `how` is 'pass', 'fail' or 'hang'."""
    try:
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", "-x", "-q", "--no-header", "-p", "no:cacheprovider"],
            cwd=ROOT, capture_output=True, text=True, env=_suite_env(),
            timeout=SUITE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return False, "hang"
    return proc.returncode == 0, ("pass" if proc.returncode == 0 else "fail")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="print the mutants and exit")
    parser.add_argument("--only", help="substring filter on the mutant name")
    args = parser.parse_args()

    mutants = [m for m in MUTANTS if not args.only or args.only in m.name]
    if not mutants:
        print("no mutant matches that filter", file=sys.stderr)
        return 2
    if args.list:
        for m in mutants:
            print(f"{m.name}\n    {m.path.relative_to(ROOT)}: {m.breaks}")
        return 0

    signal.signal(signal.SIGTERM, _restore_and_die)
    signal.signal(signal.SIGINT, _restore_and_die)
    before = {m.path: digest(m.path) for m in mutants}

    caches = purge_bytecode()
    if caches:
        print(f"Cleared {caches} stale __pycache__ director(ies).")
    print("Baseline: running the suite unmutated ...", flush=True)
    baseline_ok, how = run_suite()
    if not baseline_ok:
        print(f"BASELINE {how.upper()}S. Fix the suite before measuring anything.", file=sys.stderr)
        return 2
    print("Baseline green.\n", flush=True)

    killed: list[str] = []
    survived: list[str] = []
    errored: list[str] = []

    for mutant in mutants:
        original = mutant.path.read_text(encoding="utf-8")
        if mutant.old not in original:
            errored.append(f"{mutant.name}: target text not found in {mutant.path.name}")
            print(f"  ERROR         {mutant.name} — target text not found", flush=True)
            continue
        mutated = original.replace(mutant.old, mutant.new, 1)
        if mutated == original:
            errored.append(f"{mutant.name}: replacement was a no-op")
            print(f"  ERROR         {mutant.name} — replacement changed nothing", flush=True)
            continue
        _IN_FLIGHT[mutant.path] = original
        mutant.path.write_text(mutated, encoding="utf-8")
        # The whole reason this harness is trustworthy: confirm the bytes on disk moved.
        assert mutant.path.read_text(encoding="utf-8") == mutated
        try:
            survived_this, how = run_suite()
        finally:
            mutant.path.write_text(original, encoding="utf-8")
            assert mutant.path.read_text(encoding="utf-8") == original
            _IN_FLIGHT.pop(mutant.path, None)
        if survived_this:
            survived.append(f"{mutant.name} — {mutant.breaks}")
            print(f"  SURVIVED      {mutant.name}", flush=True)
        else:
            label = "killed (hang)" if how == "hang" else "killed"
            killed.append(mutant.name)
            print(f"  {label:<13} {mutant.name}", flush=True)

    drifted = [str(p) for p, d in before.items() if digest(p) != d]
    if drifted:
        print(f"\nSOURCE TREE IS DIRTY after the run: {drifted}", file=sys.stderr)
        print("A mutant was left behind. Restore from git before trusting any result.", file=sys.stderr)
        return 2

    print(f"\n{len(killed)}/{len(mutants)} mutants killed, {len(survived)} survived, {len(errored)} errors")
    for line in survived:
        print(f"  SURVIVED: {line}")
    for line in errored:
        print(f"  ERROR: {line}")
    return 0 if not survived and not errored else 1


if __name__ == "__main__":
    raise SystemExit(main())
