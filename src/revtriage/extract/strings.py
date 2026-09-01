"""String extraction, ASCII and UTF-16LE.

UTF-16LE is not an afterthought: the Windows API is wide-character, so the URL, the
mutex name and the registry path in a Windows sample are frequently invisible to an
ASCII-only `strings`. Missing them is the classic way a triage tool reports a clean file
that is not clean.
"""

from __future__ import annotations

import re

def extract_strings(data: bytes, minimum: int = 5, limit: int = 40000) -> list[str]:
    """Printable runs of at least `minimum` characters, ASCII then UTF-16LE, deduplicated
    while preserving first-seen order (order is what makes a diff between two samples
    readable)."""
    found: list[str] = []
    seen: set[str] = set()

    for pattern, decoder in (
        (re.compile(rb"[\x20-\x7e]{%d,}" % minimum), lambda m: m.decode("ascii")),
        (re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum), lambda m: m.decode("utf-16-le")),
    ):
        for match in pattern.finditer(data):
            if len(found) >= limit:
                return found
            try:
                value = decoder(match.group())
            except UnicodeDecodeError:  # pragma: no cover - guarded by the pattern
                continue
            if value not in seen:
                seen.add(value)
                found.append(value)
    return found
