"""Base64, hex, percent and character-code decoding.

These are the cheap layers — the ones a dropper uses because they survive being pasted
into a document, not because they resist analysis. They are also where most real
indicators hide, so the goal here is recall: try every plausible run, and let
`score.is_interesting` throw away what decoded into noise.
"""

from __future__ import annotations

import base64
import binascii
import re

#: 24 characters is 18 decoded bytes — short enough to catch a hostname, long enough that
#: ordinary identifiers and hashes in a file do not each become a candidate.
_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
_B64URL_RUN = re.compile(rb"[A-Za-z0-9_-]{24,}={0,2}")
_HEX_RUN = re.compile(rb"(?:\\x[0-9A-Fa-f]{2}){8,}")
_BARE_HEX_RUN = re.compile(rb"(?:[0-9A-Fa-f]{2}){16,}")
_PERCENT_RUN = re.compile(rb"(?:%[0-9A-Fa-f]{2}){8,}")
_HTML_ENTITY_RUN = re.compile(rb"(?:&#x?[0-9A-Fa-f]{1,4};){6,}")
_FROM_CHARCODE = re.compile(
    rb"fromCharCode\s*\(\s*(?P<args>[0-9xXa-fA-F\s,+\-*]{6,4000}?)\s*\)", re.IGNORECASE
)
_VBS_CHR = re.compile(rb"(?:Chr[W$]?\s*\(\s*\d{1,5}\s*\)\s*[&+]?\s*){4,}", re.IGNORECASE)
_PS_CHAR = re.compile(rb"(?:\[char\]\s*\d{1,5}\s*[,+]?\s*){4,}", re.IGNORECASE)

MAX_CANDIDATES = 64


def decode_all(data: bytes) -> list[tuple[str, str, bytes]]:
    """Every encoding candidate found in `data`, as (technique, description, decoded)."""
    out: list[tuple[str, str, bytes]] = []
    out.extend(_base64_candidates(data))
    out.extend(_char_codes(data))
    out.extend(_escaped(data))
    return out[: MAX_CANDIDATES * 4]


def _base64_candidates(data: bytes) -> list[tuple[str, str, bytes]]:
    out: list[tuple[str, str, bytes]] = []
    for pattern, name, decoder in (
        (_B64_RUN, "base64", base64.b64decode),
        (_B64URL_RUN, "base64url", base64.urlsafe_b64decode),
    ):
        for match in pattern.finditer(data):
            if len(out) >= MAX_CANDIDATES:
                break
            blob = match.group()
            padded = blob + b"=" * (-len(blob) % 4)
            try:
                decoded = decoder(padded)
            except (binascii.Error, ValueError):
                continue
            if len(decoded) < 8:
                continue
            out.append((name, f"{name} run of {len(blob)} chars at offset {match.start()}", decoded))
            # A base64 blob produced by PowerShell holds UTF-16LE text; a plain UTF-8
            # decode of it reads as text with a NUL between every character, which no
            # rule matches. Offer the wide interpretation as its own candidate.
            if len(decoded) >= 8 and decoded[1::2].count(0) > len(decoded) // 4:
                try:
                    wide = decoded.decode("utf-16-le").encode("utf-8")
                except (UnicodeDecodeError, UnicodeEncodeError):
                    continue
                out.append((f"{name}+utf16le", f"{name} run decoded as UTF-16LE text", wide))
    return out


def _char_codes(data: bytes) -> list[tuple[str, str, bytes]]:
    out: list[tuple[str, str, bytes]] = []

    for match in _FROM_CHARCODE.finditer(data):
        codes = _numbers(match.group("args"))
        if len(codes) >= 4:
            out.append(("fromCharCode", f"String.fromCharCode with {len(codes)} codes", _to_bytes(codes)))

    for pattern, name in ((_VBS_CHR, "vbs-chr"), (_PS_CHAR, "powershell-char")):
        for match in pattern.finditer(data):
            codes = _numbers(match.group())
            if len(codes) >= 4:
                out.append((name, f"{name} sequence of {len(codes)} codes", _to_bytes(codes)))

    return out[:MAX_CANDIDATES]


def _escaped(data: bytes) -> list[tuple[str, str, bytes]]:
    out: list[tuple[str, str, bytes]] = []

    for match in _HEX_RUN.finditer(data):
        raw = match.group().replace(b"\\x", b"")
        try:
            out.append(("hex-escape", rf"\x-escaped run of {len(raw) // 2} bytes", binascii.unhexlify(raw)))
        except binascii.Error:
            continue

    for match in _PERCENT_RUN.finditer(data):
        raw = match.group().replace(b"%", b"")
        try:
            out.append(("percent-encoding", f"percent-encoded run of {len(raw) // 2} bytes", binascii.unhexlify(raw)))
        except binascii.Error:
            continue

    for match in _HTML_ENTITY_RUN.finditer(data):
        codes = []
        for entity in re.findall(rb"&#(x?)([0-9A-Fa-f]{1,4});", match.group()):
            prefix, value = entity
            codes.append(int(value, 16 if prefix else 10))
        if codes:
            out.append(("html-entity", f"HTML entity run of {len(codes)} codes", _to_bytes(codes)))

    for match in _BARE_HEX_RUN.finditer(data):
        if len(out) >= MAX_CANDIDATES:
            break
        raw = match.group()
        try:
            decoded = binascii.unhexlify(raw)
        except binascii.Error:
            continue
        out.append(("hex-string", f"contiguous hex string of {len(decoded)} bytes", decoded))

    return out[:MAX_CANDIDATES]


def _numbers(blob: bytes) -> list[int]:
    values: list[int] = []
    for token in re.findall(rb"0[xX][0-9A-Fa-f]+|\d+", blob):
        try:
            values.append(int(token, 16 if token[:2].lower() == b"0x" else 10))
        except ValueError:
            continue
    return values


def _to_bytes(codes: list[int]) -> bytes:
    return bytes(code & 0xFF for code in codes if 0 <= code <= 0x10FFFF)
