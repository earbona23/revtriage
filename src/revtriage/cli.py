"""Command-line entry point.

One command, one file, one or more report formats. The tool reads the sample, never runs
it, and writes only where told. The exit code can optionally carry the verdict so
revtriage drops into a CI gate — but only when asked, because a triage tool that fails a
build by default the first time it sees a packed installer teaches people to remove it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import PROJECT_URL, __version__
from .analyze import analyze
from .license import load_license
from .report import to_json, to_markdown, to_stix_bundle

_FORMATS = ("md", "json", "stix")

_EXIT_BY_VERDICT = {"benign": 0, "suspicious": 10, "likely-malicious": 20, "malicious": 30}

MAX_INPUT_BYTES = 256 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revtriage",
        description="Offline reverse-engineering triage of a suspicious file. "
        "Nothing is uploaded. The sample is parsed, never executed.",
        epilog=f"Docs and source: {PROJECT_URL}",
    )
    parser.add_argument("file", help="path to the file to triage")
    parser.add_argument(
        "-f", "--format", choices=(*_FORMATS, "all"), default="md",
        help="report format (default: md). 'all' writes every format next to --out.",
    )
    parser.add_argument(
        "-o", "--out",
        help="write the report here instead of stdout. With --format all, used as a basename.",
    )
    parser.add_argument("--license", help="a PRO licence token (overrides env/config)")
    parser.add_argument(
        "--min-strings", type=int, default=5, metavar="N",
        help="minimum length for extracted strings (default: 5)",
    )
    parser.add_argument(
        "--exit-code", action="store_true",
        help="set the process exit code from the verdict (benign 0 … malicious 30)",
    )
    parser.add_argument("--version", action="version", version=f"revtriage {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    path = Path(args.file)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"revtriage: cannot read {args.file}: {exc}", file=sys.stderr)
        return 2
    if len(raw) > MAX_INPUT_BYTES:
        print(
            f"revtriage: {args.file} is {len(raw)} bytes, above the {MAX_INPUT_BYTES}-byte limit",
            file=sys.stderr,
        )
        return 2

    license_result = load_license(args.license)
    triage = analyze(raw, name=path.name, license_result=license_result, strings_min=args.min_strings)

    rendered = {
        "md": lambda: to_markdown(triage),
        "json": lambda: to_json(triage),
        "stix": lambda: _stix_text(triage),
    }

    if args.format == "all":
        _write_all(args.out, rendered)
    else:
        text = rendered[args.format]()
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"revtriage: wrote {args.out}", file=sys.stderr)
        else:
            print(text)

    if args.exit_code and triage.score:
        return _EXIT_BY_VERDICT.get(triage.score.verdict, 0)
    return 0


def _stix_text(triage) -> str:
    import json

    return json.dumps(to_stix_bundle(triage), indent=2, ensure_ascii=False)


def _write_all(out: str | None, rendered: dict) -> None:
    base = out or "revtriage-report"
    suffix = {"md": ".md", "json": ".json", "stix": ".stix.json"}
    for fmt, render in rendered.items():
        target = Path(f"{base}{suffix[fmt]}")
        target.write_text(render(), encoding="utf-8")
        print(f"revtriage: wrote {target}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
