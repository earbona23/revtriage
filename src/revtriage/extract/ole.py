"""OLE2 / Compound File Binary reader, plus MS-OVBA decompression.

Legacy Office documents (`.doc`, `.xls`) and the `vbaProject.bin` inside modern ones are
Compound File Binary containers — a FAT-like filesystem in a file. Macro source lives in
streams inside it, compressed with the run-length scheme defined in MS-OVBA.

Both are implemented here because the alternative — telling the analyst "this document
has macros" without showing the code — is the answer they already had from the file
extension. The code is what carries the URL, the `Shell` call and the persistence key.

References: [MS-CFB] Compound File Binary File Format, [MS-OVBA] section 2.4.1
(Compression and Decompression).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC

TYPE_STORAGE = 1
TYPE_STREAM = 2
TYPE_ROOT = 5

#: Guards against a crafted FAT whose chain never terminates.
MAX_CHAIN = 65536


@dataclass
class Entry:
    name: str
    kind: int
    size: int
    start: int
    path: str = ""


class OleFile:
    """A parsed compound file. Raises `ValueError` only when the header itself is not CFB."""

    def __init__(self, data: bytes):
        if len(data) < 512 or data[:8] != OLE_MAGIC:
            raise ValueError("not an OLE compound file")
        self.data = data
        (sector_shift,) = struct.unpack_from("<H", data, 0x1E)
        (mini_shift,) = struct.unpack_from("<H", data, 0x20)
        self.sector_size = 1 << sector_shift if 6 <= sector_shift <= 20 else 512
        self.mini_sector_size = 1 << mini_shift if 3 <= mini_shift <= 12 else 64
        (self.fat_sector_count,) = struct.unpack_from("<I", data, 0x2C)
        (self.first_dir_sector,) = struct.unpack_from("<I", data, 0x30)
        (self.mini_cutoff,) = struct.unpack_from("<I", data, 0x38)
        (self.first_minifat_sector,) = struct.unpack_from("<I", data, 0x3C)
        (self.minifat_count,) = struct.unpack_from("<I", data, 0x40)
        (self.first_difat_sector,) = struct.unpack_from("<I", data, 0x44)
        (self.difat_count,) = struct.unpack_from("<I", data, 0x48)
        self.notes: list[str] = []
        self.fat = self._read_fat()
        self.entries = self._read_directory()
        self.minifat = self._read_minifat()
        self._mini_stream = self._read_mini_stream()

    # -- sector plumbing -------------------------------------------------------------

    def _sector(self, index: int) -> bytes:
        start = (index + 1) * self.sector_size
        if start < 0 or start >= len(self.data):
            return b""
        return self.data[start : start + self.sector_size]

    def _read_fat(self) -> list[int]:
        difat: list[int] = []
        for i in range(109):
            (value,) = struct.unpack_from("<I", self.data, 0x4C + i * 4)
            if value <= FATSECT and value != FREESECT:
                difat.append(value)
        # Extra DIFAT sectors, chained. Bounded so a self-referential chain cannot spin.
        sector = self.first_difat_sector
        for _ in range(min(self.difat_count, 4096)):
            if sector in (ENDOFCHAIN, FREESECT):
                break
            block = self._sector(sector)
            if len(block) < self.sector_size:
                break
            count = self.sector_size // 4 - 1
            for i in range(count):
                (value,) = struct.unpack_from("<I", block, i * 4)
                if value != FREESECT:
                    difat.append(value)
            (sector,) = struct.unpack_from("<I", block, count * 4)

        fat: list[int] = []
        for sector_index in difat[: max(self.fat_sector_count, len(difat))]:
            block = self._sector(sector_index)
            for i in range(len(block) // 4):
                (value,) = struct.unpack_from("<I", block, i * 4)
                fat.append(value)
        return fat

    def _chain(self, start: int) -> list[int]:
        chain: list[int] = []
        seen: set[int] = set()
        sector = start
        while sector not in (ENDOFCHAIN, FREESECT) and len(chain) < MAX_CHAIN:
            if sector in seen or sector >= len(self.fat):
                if sector in seen:
                    self.notes.append("ole:fat-chain-loop")
                break
            seen.add(sector)
            chain.append(sector)
            sector = self.fat[sector]
        return chain

    def _read_stream(self, start: int, size: int) -> bytes:
        out = bytearray()
        for sector in self._chain(start):
            out += self._sector(sector)
            if len(out) >= size:
                break
        return bytes(out[:size])

    def _read_minifat(self) -> list[int]:
        minifat: list[int] = []
        for sector in self._chain(self.first_minifat_sector)[: max(self.minifat_count, 1) + 64]:
            block = self._sector(sector)
            for i in range(len(block) // 4):
                (value,) = struct.unpack_from("<I", block, i * 4)
                minifat.append(value)
        return minifat

    def _read_mini_stream(self) -> bytes:
        root = next((e for e in self.entries if e.kind == TYPE_ROOT), None)
        if root is None:
            return b""
        return self._read_stream(root.start, root.size)

    def _read_mini(self, start: int, size: int) -> bytes:
        out = bytearray()
        sector = start
        seen: set[int] = set()
        while sector not in (ENDOFCHAIN, FREESECT) and len(out) < size and len(seen) < MAX_CHAIN:
            if sector in seen or sector >= len(self.minifat):
                break
            seen.add(sector)
            offset = sector * self.mini_sector_size
            out += self._mini_stream[offset : offset + self.mini_sector_size]
            sector = self.minifat[sector]
        return bytes(out[:size])

    # -- directory -------------------------------------------------------------------

    def _read_directory(self) -> list[Entry]:
        raw: list[tuple[Entry, int, int, int]] = []
        for sector in self._chain(self.first_dir_sector):
            block = self._sector(sector)
            for offset in range(0, len(block) - 127, 128):
                (name_len,) = struct.unpack_from("<H", block, offset + 0x40)
                kind = block[offset + 0x42]
                if kind not in (TYPE_STORAGE, TYPE_STREAM, TYPE_ROOT):
                    continue
                name = block[offset : offset + max(min(name_len, 64), 2) - 2].decode(
                    "utf-16-le", errors="replace"
                )
                left, right, child = struct.unpack_from("<III", block, offset + 0x44)
                (start,) = struct.unpack_from("<I", block, offset + 0x74)
                (size,) = struct.unpack_from("<Q", block, offset + 0x78)
                raw.append((Entry(name=name, kind=kind, size=size, start=start), left, right, child))

        # Reconstruct paths by walking the red-black tree. A malformed tree just yields
        # flat names, which is still enough to answer "is there a VBA storage in here".
        entries = [item[0] for item in raw]
        if raw:
            self._assign_paths(raw, 0, "")
        for entry in entries:
            if not entry.path:
                entry.path = entry.name
        return entries

    def _assign_paths(self, raw, index: int, prefix: str, depth: int = 0) -> None:
        if depth > 64 or index >= len(raw) or index in (FREESECT, ENDOFCHAIN):
            return
        entry, left, right, child = raw[index]
        if entry.path:
            return
        entry.path = f"{prefix}/{entry.name}" if prefix else entry.name
        if left < len(raw):
            self._assign_paths(raw, left, prefix, depth + 1)
        if right < len(raw):
            self._assign_paths(raw, right, prefix, depth + 1)
        if child < len(raw):
            base = "" if entry.kind == TYPE_ROOT else entry.path
            self._assign_paths(raw, child, base, depth + 1)

    # -- public ----------------------------------------------------------------------

    def streams(self) -> list[Entry]:
        return [e for e in self.entries if e.kind == TYPE_STREAM and e.size > 0]

    def read(self, entry: Entry) -> bytes:
        if entry.size < self.mini_cutoff:
            return self._read_mini(entry.start, entry.size)
        return self._read_stream(entry.start, entry.size)


def decompress_vba(data: bytes) -> bytes:
    """Decompress an MS-OVBA CompressedContainer.

    The format is a byte-oriented LZ77 variant: a 0x01 signature byte, then chunks of at
    most 4096 decompressed bytes. Each chunk is a sequence of groups; a FlagByte says
    which of the next eight tokens are literals and which are (offset, length) copies.
    The bit split inside a copy token is *positional* — it depends on how far into the
    chunk the decompressor already is — which is the part naive implementations get wrong.
    """
    if not data or data[0] != 0x01:
        raise ValueError("not a compressed VBA container (missing 0x01 signature byte)")

    out = bytearray()
    position = 1
    while position + 2 <= len(data):
        (header,) = struct.unpack_from("<H", data, position)
        position += 2
        size = (header & 0x0FFF) + 3
        compressed = bool(header & 0x8000)
        end = position + size - 2
        if end > len(data):
            end = len(data)
        chunk_start = len(out)

        if not compressed:
            out += data[position:end]
            position = end
            continue

        while position < end:
            flag = data[position]
            position += 1
            for bit in range(8):
                if position >= end:
                    break
                if not (flag >> bit) & 1:
                    out.append(data[position])
                    position += 1
                    continue
                if position + 2 > end:
                    position = end
                    break
                (token,) = struct.unpack_from("<H", data, position)
                position += 2
                difference = len(out) - chunk_start
                bit_count = max(_bits_needed(difference), 4)
                length_mask = 0xFFFF >> bit_count
                offset_mask = (~length_mask) & 0xFFFF
                length = (token & length_mask) + 3
                offset = ((token & offset_mask) >> (16 - bit_count)) + 1
                source = len(out) - offset
                if source < 0:
                    raise ValueError("copy token points before the start of the output")
                # Copied one byte at a time on purpose: overlapping copies are legal and
                # are how the format expresses runs.
                for _ in range(length):
                    out.append(out[source])
                    source += 1
    return bytes(out)


def _bits_needed(value: int) -> int:
    """Number of bits to represent `value`; 0 and 1 both need 0 by the spec's definition."""
    bits = 0
    while (1 << bits) < value:
        bits += 1
    return bits


def find_vba_source(stream: bytes) -> str | None:
    """Recover macro source from a VBA module stream.

    The compressed container does not start at offset 0: the stream begins with a
    performance cache whose length is recorded elsewhere (the `dir` stream). Rather than
    parse that too, every plausible container start is tried and the longest text that
    decompresses wins. This is a heuristic — it is documented as one — and it fails
    closed: no candidate decompresses, no source is claimed.
    """
    best: bytes | None = None
    for offset in _candidate_offsets(stream):
        try:
            decoded = decompress_vba(stream[offset:])
        except (ValueError, IndexError, struct.error):
            continue
        if len(decoded) > 16 and (best is None or len(decoded) > len(best)):
            best = decoded
    if best is None:
        return None
    return best.decode("latin-1", errors="replace")


def _candidate_offsets(stream: bytes, limit: int = 64) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        index = stream.find(b"\x01", start)
        if index == -1:
            break
        offsets.append(index)
        start = index + 1
    return offsets
