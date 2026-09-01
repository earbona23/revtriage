"""gzip / zlib / raw-deflate unwrapping."""

from __future__ import annotations

import bz2
import gzip
import lzma
import zlib

MAX_OUTPUT = 8 * 1024 * 1024


def unwrap(data: bytes) -> list[tuple[str, str, bytes]]:
    """Return (technique, description, decompressed) for every container that opens.

    Decompression is bounded with `decompressobj(max_length=...)` rather than a plain
    `decompress`, because a zip bomb is a real anti-analysis technique and an unbounded
    call would hand the sample a way to end the analysis by exhausting memory.
    """
    out: list[tuple[str, str, bytes]] = []

    if data[:2] == b"\x1f\x8b":
        try:
            decoded = gzip.decompress(data)[:MAX_OUTPUT]
            out.append(("gzip", "gzip stream decompressed", decoded))
        except (OSError, EOFError, zlib.error):
            pass

    if data[:6] in (b"\xfd7zXZ\x00",) or data[:5] == b"\xfd7zX":
        try:
            out.append(("xz", "xz/lzma stream decompressed", lzma.decompress(data)[:MAX_OUTPUT]))
        except lzma.LZMAError:
            pass

    if data[:3] == b"BZh":
        try:
            out.append(("bzip2", "bzip2 stream decompressed", bz2.decompress(data)[:MAX_OUTPUT]))
        except (OSError, ValueError):
            pass

    # zlib with a header, and raw deflate without one. Raw deflate is what PowerShell's
    # DeflateStream and many droppers emit after base64, so it must be tried explicitly.
    for wbits, technique, description in (
        (15, "zlib", "zlib stream decompressed"),
        (-15, "deflate", "raw deflate stream decompressed"),
    ):
        try:
            obj = zlib.decompressobj(wbits)
            decoded = obj.decompress(data, MAX_OUTPUT)
        except zlib.error:
            continue
        if len(decoded) >= 16:
            out.append((technique, description, decoded))

    return out
