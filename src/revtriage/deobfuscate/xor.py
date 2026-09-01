"""Single-byte XOR recovery.

The naive approach — decode the whole buffer with each of the 255 keys and score the
result — is O(255 × n) of Python-level byte work and is unusable on a multi-megabyte
sample. This module inverts the search instead:

    for each key k, look for  MARKER ^ k  in the original bytes

The scan is done by `bytes.find`, which is a C memchr-based search, so 255 keys against a
handful of markers is a few hundred fast passes rather than a quarter of a gigabyte of
Python loops. A hit tells you the key *and* the offset, and only then is a bounded region
actually decoded.

There are two anchor families, because XOR is applied to two very different things:

* **Plaintext anchors** work when the XORed content is text or a PE image.
* **Container anchors** (gzip, zlib, PE, ELF, ZIP magic) work when the XORed content is
  already compressed — the case where every content-based score is blind, since
  compressed bytes look like noise no matter which key you try. A short magic number
  produces false hits by itself, so a compressed-container hit is only reported once the
  candidate has actually been decompressed. Verification, not a heuristic.

Two behaviours are deliberate:

* Key 0x00 is never reported. XOR with zero is the identity function, so "the file
  decodes with key 0" is true of every file and means nothing.
* A whole-buffer brute force with entropy/English scoring still runs, but only for small
  blobs, where it is cheap and where the marker search has nothing to grip on.
"""

from __future__ import annotations

import bz2
import re
import zlib
from collections import Counter

from ..util import printable_ratio

#: Anchors that survive a single-byte XOR: each is a plain byte string an implant is
#: overwhelmingly likely to contain somewhere in its plaintext.
ANCHORS: tuple[bytes, ...] = (
    b"This program cannot be run in DOS mode",
    b"http://",
    b"https://",
    b"kernel32.dll",
    b"KERNEL32.DLL",
    b"cmd.exe",
    b"powershell",
    b"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"User-Agent:",
    b"/bin/sh",
)

#: Magic numbers worth searching for XORed. Each maps to how a hit is confirmed:
#: 'decompress' candidates must actually open, 'magic' candidates are long enough that
#: the signature alone is evidence.
CONTAINER_ANCHORS: tuple[tuple[bytes, str, str], ...] = (
    (b"\x1f\x8b\x08", "gzip", "decompress"),
    (b"\x78\x9c", "zlib", "decompress"),
    (b"\x78\x01", "zlib (no compression)", "decompress"),
    (b"\x78\xda", "zlib (best compression)", "decompress"),
    (b"BZh9", "bzip2", "decompress"),
    (b"MZ\x90\x00", "PE image", "magic"),
    (b"\x7fELF", "ELF image", "magic"),
    (b"PK\x03\x04", "ZIP archive", "magic"),
)

#: Above this size the whole buffer is never decoded speculatively; only a window is.
WINDOW = 16384
SMALL_BLOB = 4096
#: How much of a candidate is decoded to test whether a compressed container really opens.
VERIFY_WINDOW = 4096
#: Colliding magic positions tested per (key, magic) pair before giving up.
MAX_VERIFY_ATTEMPTS = 8


def find_keys(data: bytes, anchors: tuple[bytes, ...] = ANCHORS) -> list[tuple[int, int, bytes]]:
    """Return (key, offset, anchor) for every single-byte key whose anchor appears.

    Only the first hit per key is reported: one confirmed anchor is proof of the key, and
    further hits add report noise without adding information.
    """
    hits: list[tuple[int, int, bytes]] = []
    seen_keys: set[int] = set()
    for key in range(1, 256):
        for anchor in anchors:
            needle = bytes(b ^ key for b in anchor)
            index = data.find(needle)
            if index != -1:
                if key not in seen_keys:
                    seen_keys.add(key)
                    hits.append((key, index, anchor))
                break
    return hits


def decode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def find_container_keys(data: bytes) -> list[tuple[int, int, str]]:
    """Return (key, offset, container) for XORed container magics that verify."""
    hits: list[tuple[int, int, str]] = []
    for key in range(1, 256):
        hit = _container_hit_for_key(data, key)
        if hit is not None:
            hits.append(hit)
    return hits


def _container_hit_for_key(data: bytes, key: int) -> tuple[int, int, str] | None:
    """First verified container magic for one key, or None."""
    for magic, label, confirmation in CONTAINER_ANCHORS:
        needle = bytes(b ^ key for b in magic)
        start = 0
        # A two-byte magic collides often, so several positions may need testing before
        # one verifies. The attempt count is capped so a crafted file full of collisions
        # cannot turn this into a quadratic scan.
        for _ in range(MAX_VERIFY_ATTEMPTS):
            index = data.find(needle, start)
            if index == -1:
                break
            if confirmation == "magic" or _opens(decode(data[index : index + VERIFY_WINDOW], key)):
                return key, index, label
            start = index + 1
    return None


def _opens(candidate: bytes) -> bool:
    """True when `candidate` starts a compressed stream that actually decompresses.

    A truncated window is expected — only the first bytes are checked — so an 'unfinished
    stream' error still counts as a successful open.
    """
    if len(candidate) < 16:
        return False
    if candidate[:2] == b"\x1f\x8b":
        try:
            zlib.decompressobj(31).decompress(candidate, 4096)
            return True
        except zlib.error:
            return False
    if candidate[:3] == b"BZh":
        try:
            return len(bz2.BZ2Decompressor().decompress(candidate, 4096)) > 0
        except (OSError, ValueError, EOFError):
            return False
    try:
        decoded = zlib.decompressobj(15).decompress(candidate, 4096)
    except zlib.error:
        return False
    return len(decoded) >= 8


def recover(data: bytes) -> list[tuple[str, str, bytes]]:
    """Every plausible single-byte XOR decode of `data`."""
    out: list[tuple[str, str, bytes]] = []
    claimed: set[int] = set()

    for key, offset, container in find_container_keys(data):
        claimed.add(key)
        body = decode(data[offset : offset + max(WINDOW, VERIFY_WINDOW)], key)
        out.append(
            (
                f"xor-{key:#04x}",
                f"single-byte XOR key {key:#04x} revealing a {container} at offset {offset}",
                body,
            )
        )

    for key, offset, anchor in find_keys(data):
        if key in claimed:
            continue
        if len(data) <= WINDOW:
            body = decode(data, key)
            where = "whole buffer"
        else:
            start = max(0, offset - WINDOW // 2)
            body = decode(data[start : start + WINDOW], key)
            where = f"{WINDOW} byte window at offset {start}"
        out.append(
            (
                f"xor-{key:#04x}",
                f"single-byte XOR key {key:#04x}, anchored on {anchor[:24]!r} ({where})",
                body,
            )
        )

    if not out and len(data) <= SMALL_BLOB:
        best = _brute_force_small(data)
        if best is not None:
            key, body = best
            out.append(
                (
                    f"xor-{key:#04x}",
                    f"single-byte XOR key {key:#04x}, recovered by scoring (no anchor matched)",
                    body,
                )
            )
    return out


def _brute_force_small(data: bytes) -> tuple[int, bytes] | None:
    """Score all 255 keys on a short blob and return the clear winner, if there is one."""
    if len(data) < 16:
        return None
    scored: list[tuple[float, int, bytes]] = []
    for key in range(1, 256):
        body = decode(data, key)
        scored.append((_readability(body), key, body))
    scored.sort(reverse=True, key=lambda item: item[0])
    top_score, key, body = scored[0]
    runner_up = scored[1][0] if len(scored) > 1 else 0.0
    # Require both an absolute quality bar and a margin over the second-best key. Without
    # the margin, near-uniform random data always produces a "winner" that means nothing.
    if top_score >= 0.75 and top_score - runner_up >= 0.05:
        return key, body
    return None


_LETTERS = re.compile(rb"[A-Za-z]")


def _readability(data: bytes) -> float:
    """0.0–1.0. Blends printability, letter density and byte-value spread."""
    printable = printable_ratio(data)
    if printable < 0.6:
        return 0.0
    letters = len(_LETTERS.findall(data)) / len(data)
    distinct = len(Counter(data))
    # Real text uses a modest slice of the byte space; random data uses most of it.
    spread = 1.0 if distinct <= 96 else max(0.0, 1.0 - (distinct - 96) / 160)
    return 0.5 * printable + 0.3 * min(letters * 2, 1.0) + 0.2 * spread
