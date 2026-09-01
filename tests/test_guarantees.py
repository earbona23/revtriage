"""The structural guarantees, asserted over the source tree rather than promised in prose.

revtriage's three load-bearing claims are negative ones: it never executes the sample, it
never opens a socket, and it has no third-party runtime dependency. Negative claims rot
silently — nothing fails when someone adds `import requests` for a "quick" enrichment, and
the README goes on saying otherwise for years.

So they are checked here, by parsing every module in `src/` and inspecting what it imports
and what it calls. A grep would be fooled by a comment or by the detection pattern
`b"eval("`, which is a rule looking for eval in a *sample*, not a call. The AST is not.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "revtriage"

#: Anything that can reach the network. A tool that promises the sample never learns it is
#: being analysed cannot resolve a hostname, not even for a "harmless" version check.
NETWORK_MODULES = {
    "socket", "ssl", "http", "urllib", "urllib2", "urllib3", "ftplib", "smtplib",
    "poplib", "imaplib", "telnetlib", "requests", "httpx", "aiohttp", "xmlrpc",
    "webbrowser", "asyncio",
}

#: Anything that can run code: the sample's, or anything derived from it.
EXECUTION_MODULES = {"subprocess", "multiprocessing", "pickle", "marshal", "shelve", "ctypes", "runpy", "pty"}

#: Builtins that turn data into behaviour.
EXECUTION_CALLS = {"eval", "exec", "compile", "__import__", "breakpoint"}

#: os.<name> that spawns.
OS_SPAWN = {"system", "popen", "execv", "execve", "execl", "execlp", "execvp", "spawnl", "spawnv", "fork", "posix_spawn"}


def modules() -> list[tuple[Path, ast.Module]]:
    found = []
    for path in sorted(SRC.rglob("*.py")):
        found.append((path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))))
    assert len(found) > 20, "the source tree moved; this test is no longer looking at it"
    return found


def imported_roots(tree: ast.Module) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    return roots


def test_no_module_can_reach_the_network():
    offenders = [
        f"{path.relative_to(SRC)}: {sorted(imported_roots(tree) & NETWORK_MODULES)}"
        for path, tree in modules()
        if imported_roots(tree) & NETWORK_MODULES
    ]
    assert not offenders, "revtriage must have no way to open a connection:\n" + "\n".join(offenders)


def test_no_module_can_execute_anything():
    offenders = [
        f"{path.relative_to(SRC)}: {sorted(imported_roots(tree) & EXECUTION_MODULES)}"
        for path, tree in modules()
        if imported_roots(tree) & EXECUTION_MODULES
    ]
    assert not offenders, "revtriage parses samples, it never runs them:\n" + "\n".join(offenders)


def test_no_call_turns_data_into_code():
    offenders: list[str] = []
    for path, tree in modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in EXECUTION_CALLS:
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}: {func.id}()")
            elif (
                isinstance(func, ast.Attribute)
                and func.attr in OS_SPAWN
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
            ):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}: os.{func.attr}()")
    assert not offenders, "a decoded layer must never become behaviour:\n" + "\n".join(offenders)


def test_every_runtime_import_is_standard_library():
    """`dependencies = []` is only true if nothing under src/ imports a third party."""
    stdlib = set(sys.stdlib_module_names)
    own = {"revtriage"}
    third_party: set[str] = set()
    for _, tree in modules():
        third_party |= {root for root in imported_roots(tree) if root not in stdlib and root not in own}
    assert not third_party, f"third-party imports found in the runtime package: {sorted(third_party)}"


@pytest.mark.parametrize("forbidden", sorted(NETWORK_MODULES | EXECUTION_MODULES))
def test_the_detector_would_notice(forbidden):
    """The guard is only worth having if it fires. Parse a module that does the forbidden
    thing and confirm it is flagged — otherwise a typo in a set name disarms all of the
    above while every assertion above still passes."""
    tree = ast.parse(f"import {forbidden}\n")
    assert imported_roots(tree) & (NETWORK_MODULES | EXECUTION_MODULES)
