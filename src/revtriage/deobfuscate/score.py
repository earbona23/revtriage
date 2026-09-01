"""Is this decoded blob worth keeping?

Every deobfuscation technique produces candidates, and most candidates are noise: a
base64-looking run inside a certificate, an XOR key that happens to turn a compressed
block into slightly-more-printable garbage. Without a gate, a report fills with dozens of
meaningless layers and the real one is lost in them — which is exactly the outcome the
obfuscation was aiming for.

The gate scores a candidate on three independent signals and requires a minimum. It is
deliberately conservative: a missed layer costs one indicator, a flood of false layers
costs the analyst's attention, which is the scarcer resource.
"""

from __future__ import annotations

import bz2
import re
import zlib

from ..util import printable_ratio

#: Byte sequences that make a decode obviously meaningful regardless of its readability.
MARKERS: tuple[bytes, ...] = (
    b"http://", b"https://", b"ftp://", b"\\\\",
    b"cmd.exe", b"powershell", b"rundll32", b"regsvr32", b"mshta", b"wscript", b"cscript",
    b"HKEY_", b"HKCU", b"HKLM", b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"CreateObject", b"WScript.Shell", b"Shell.Application", b"XMLHTTP", b"WinHttp",
    b"MZ\x90\x00", b"This program cannot", b"kernel32", b"VirtualAlloc", b"WriteProcessMemory",
    b"/bin/sh", b"/bin/bash", b"chmod +x", b"crontab", b"systemd",
    b"Invoke-Expression", b"IEX", b"DownloadString", b"FromBase64String",
    b"-----BEGIN", b"<script", b"eval(",
)

_ENGLISH_WORDS = (
    b" the ", b" and ", b" for ", b" this ", b" file ", b" error ", b" system ",
    b" function ", b" return ", b" object ", b" string ", b" true ", b" false ",
)

_WORDLIKE = re.compile(rb"[A-Za-z]{3,}")

#: A candidate must reach this to become a layer. Tuned so that a decode carrying any
#: single marker always qualifies, while readable-but-empty text needs real structure.
KEEP_THRESHOLD = 40


def interest(data: bytes) -> int:
    """Score a decode 0–100. Higher means more likely to be real content."""
    if len(data) < 8:
        return 0

    score = 0
    lowered = data.lower()

    marker_hits = sum(1 for marker in MARKERS if marker.lower() in lowered)
    if marker_hits:
        # One unambiguous marker is enough on its own; more only reinforces it.
        score += min(40 + 10 * (marker_hits - 1), 60)

    ratio = printable_ratio(data)
    if ratio >= 0.95:
        score += 30
    elif ratio >= 0.85:
        score += 20
    elif ratio >= 0.70:
        score += 10

    words = _WORDLIKE.findall(data[:4096])
    if len(words) >= 8:
        score += 15
    elif len(words) >= 3:
        score += 5

    score += min(sum(4 for word in _ENGLISH_WORDS if word in lowered), 12)

    # A known file signature in the decode is decisive: something was carrying a payload.
    if data[:2] == b"MZ" or data[:4] == b"\x7fELF" or data[:4] == b"PK\x03\x04" or data[:5] == b"%PDF-":
        score += 40
    elif opens_as_compressed(data):
        # Compressed bytes score zero on every readability signal — that is what
        # compression does. The only honest test is whether the stream opens, so this is
        # a verification rather than a heuristic, and it is what keeps a
        # XOR-then-gzip payload from being discarded as noise.
        score += 40

    return min(score, 100)


def opens_as_compressed(data: bytes) -> bool:
    """True when `data` begins a compressed stream that really decompresses."""
    if len(data) < 16:
        return False
    if data[:2] == b"\x1f\x8b":
        try:
            return len(zlib.decompressobj(31).decompress(data, 4096)) > 0
        except zlib.error:
            return False
    if data[:1] == b"\x78":
        try:
            return len(zlib.decompressobj(15).decompress(data, 4096)) > 0
        except zlib.error:
            return False
    if data[:3] == b"BZh":
        try:
            return len(bz2.BZ2Decompressor().decompress(data, 4096)) > 0
        except (OSError, ValueError, EOFError):
            return False
    return False


def is_interesting(data: bytes, threshold: int = KEEP_THRESHOLD) -> bool:
    return interest(data) >= threshold
