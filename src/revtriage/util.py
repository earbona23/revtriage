"""Small shared primitives: hashing, entropy, printability."""

from __future__ import annotations

import hashlib
import math
from collections import Counter

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def file_hashes(data: bytes) -> dict:
    """MD5/SHA-1/SHA-256. MD5 and SHA-1 are broken for collision resistance and are here
    only because threat-intel feeds and sandbox reports are still keyed on them — they
    are identifiers for lookup, never a trust decision."""
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0.0–8.0.

    Used as a *hint* about packing or encryption, never as a verdict on its own: a
    compressed resource and an encrypted payload look identical to this measurement.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def printable_ratio(data: bytes) -> float:
    """Share of bytes that are printable ASCII — the cheapest 'did that decode work?' test."""
    if not data:
        return 0.0
    return sum(1 for b in data if b in _PRINTABLE) / len(data)


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"
