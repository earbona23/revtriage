"""Minimal PE reader: sections, entropy, import table, timestamp, overlay.

Written by hand on `struct` rather than pulling in a PE library. The reason is the
threat model of this tool: it is pointed at hostile files by definition, so every line of
parsing code is attack surface an analyst has to trust. A ~200-line reader that only ever
does bounded reads and never allocates on attacker-controlled sizes is auditable in one
sitting; a general-purpose library is not. The cost is that this covers what triage
needs — not relocations, resources or .NET metadata.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from ..model import Fact
from ..util import shannon_entropy

MACHINES = {
    0x014C: "i386",
    0x0200: "IA64",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

SUBSYSTEMS = {1: "native", 2: "GUI", 3: "console", 9: "Windows CE GUI", 16: "boot application"}

#: A section this dense is either compressed, encrypted or packed. 7.2 is the customary
#: triage threshold: real x86 code sits near 6.0–6.7, compressed data above 7.5.
PACKED_ENTROPY = 7.2


def _analyse(data: bytes, ident) -> tuple[list[Fact], list[str], list[str]]:
    facts: list[Fact] = []
    imports: list[str] = []
    notes: list[str] = []

    pe_off = int(ident.details.get("pe_offset", 0))
    if pe_off <= 0 or pe_off + 24 > len(data):
        return [Fact("pe.error", "unreadable", "the PE header offset points outside the file")], [], []

    machine, section_count, timestamp = struct.unpack_from("<HHI", data, pe_off + 4)
    opt_size, characteristics = struct.unpack_from("<HH", data, pe_off + 20)

    facts.append(Fact("pe.machine", MACHINES.get(machine, f"0x{machine:04x}")))
    facts.append(Fact("pe.is_dll", bool(characteristics & 0x2000)))
    facts.append(
        Fact(
            "pe.timestamp",
            _timestamp(timestamp),
            "the compiler's claim, freely forgeable — a date in the future or at the epoch is itself suspicious",
        )
    )

    opt_off = pe_off + 24
    magic = 0
    if opt_off + 2 <= len(data):
        (magic,) = struct.unpack_from("<H", data, opt_off)
    is_pe32_plus = magic == 0x20B
    facts.append(Fact("pe.format", "PE32+" if is_pe32_plus else "PE32"))

    if opt_off + 70 <= len(data):
        (subsystem,) = struct.unpack_from("<H", data, opt_off + (68 if is_pe32_plus else 68))
        facts.append(Fact("pe.subsystem", SUBSYSTEMS.get(subsystem, str(subsystem))))

    sections = _sections(data, opt_off + opt_size, section_count)
    facts.append(Fact("pe.section_count", len(sections)))
    packed: list[str] = []
    for section in sections:
        facts.append(
            Fact(
                f"pe.section.{section['name']}",
                {
                    "virtual_size": section["virtual_size"],
                    "raw_size": section["raw_size"],
                    "entropy": round(section["entropy"], 2),
                    "executable": section["executable"],
                },
            )
        )
        if section["entropy"] >= PACKED_ENTROPY and section["raw_size"] >= 512:
            packed.append(section["name"])
        # A section whose virtual size dwarfs its on-disk size is the classic unpacking
        # stub: the loader reserves room the file does not contain, and the packer fills
        # it at runtime.
        if section["raw_size"] and section["virtual_size"] > section["raw_size"] * 4:
            notes.append(f"pe:section-virtual-size-inflated:{section['name']}")

    if packed:
        facts.append(Fact("pe.high_entropy_sections", packed, f"entropy >= {PACKED_ENTROPY} bits/byte"))
        notes.append("pe:high-entropy-section")

    directories = _data_directories(data, opt_off, is_pe32_plus)
    import_rva, import_size = directories.get(1, (0, 0))
    if import_rva:
        imports = _imports(data, sections, import_rva)
        facts.append(Fact("pe.import_count", len(imports)))
        if not imports:
            notes.append("pe:import-table-unreadable")
            facts.append(
                Fact(
                    "pe.import_table",
                    "unreadable",
                    "the directory exists but no descriptor parsed — typical of a packed or deliberately corrupted sample",
                )
            )
    else:
        # No import directory at all: nothing is linked statically against the Windows
        # API, which almost always means the real imports are resolved at runtime.
        notes.append("pe:no-import-directory")
        facts.append(Fact("pe.import_table", "absent", "no import directory — imports are resolved at runtime"))

    if directories.get(4, (0, 0))[0]:
        facts.append(Fact("pe.has_certificate_table", True, "the file carries an Authenticode signature blob"))

    overlay = _overlay_offset(sections)
    if overlay and overlay < len(data):
        extra = len(data) - overlay
        if extra > 1024:
            facts.append(
                Fact(
                    "pe.overlay_size",
                    extra,
                    "bytes appended past the last section — installers use this, and so do droppers",
                )
            )
            notes.append("pe:overlay-present")

    return facts, imports, notes


def _timestamp(value: int) -> str:
    if value == 0:
        return "0 (zeroed)"
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return f"invalid ({value})"


def _sections(data: bytes, offset: int, count: int) -> list[dict]:
    sections: list[dict] = []
    # `count` is attacker-controlled; clamp it before it becomes a loop bound.
    for index in range(min(count, 96)):
        base = offset + index * 40
        if base + 40 > len(data):
            break
        raw_name = data[base : base + 8]
        name = raw_name.rstrip(b"\x00").decode("latin-1", errors="replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, base + 8)
        (flags,) = struct.unpack_from("<I", data, base + 36)
        body = b""
        if 0 < raw_size and raw_pointer < len(data):
            body = data[raw_pointer : raw_pointer + min(raw_size, len(data) - raw_pointer)]
        sections.append(
            {
                "name": name or f"sect{index}",
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
                "entropy": shannon_entropy(body),
                "executable": bool(flags & 0x20000000),
            }
        )
    return sections


def _data_directories(data: bytes, opt_off: int, is_pe32_plus: bool) -> dict[int, tuple[int, int]]:
    base = opt_off + (112 if is_pe32_plus else 96)
    count_off = opt_off + (108 if is_pe32_plus else 92)
    if count_off + 4 > len(data):
        return {}
    (count,) = struct.unpack_from("<I", data, count_off)
    directories: dict[int, tuple[int, int]] = {}
    for index in range(min(count, 16)):
        entry = base + index * 8
        if entry + 8 > len(data):
            break
        rva, size = struct.unpack_from("<II", data, entry)
        directories[index] = (rva, size)
    return directories


def _rva_to_offset(sections: list[dict], rva: int) -> int | None:
    for section in sections:
        start = section["virtual_address"]
        size = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + size:
            return section["raw_pointer"] + (rva - start)
    return None


def _imports(data: bytes, sections: list[dict], import_rva: int) -> list[str]:
    """Read `DLL!Function` pairs from the import descriptors.

    Bounded on every axis (descriptors, thunks, name length) so that a crafted file
    cannot turn this into an unbounded loop or a huge allocation.
    """
    table = _rva_to_offset(sections, import_rva)
    if table is None:
        return []
    names: list[str] = []
    for index in range(256):
        entry = table + index * 20
        if entry + 20 > len(data):
            break
        original_thunk, _t, _f, name_rva, first_thunk = struct.unpack_from("<IIIII", data, entry)
        if not any((original_thunk, name_rva, first_thunk)):
            break
        dll = _cstring(data, _rva_to_offset(sections, name_rva)) or "?"
        thunk_rva = original_thunk or first_thunk
        thunk = _rva_to_offset(sections, thunk_rva) if thunk_rva else None
        if thunk is None:
            continue
        for slot in range(4096):
            position = thunk + slot * 4
            if position + 4 > len(data):
                break
            (value,) = struct.unpack_from("<I", data, position)
            if value == 0:
                break
            if value & 0x80000000:
                names.append(f"{dll}!#{value & 0xFFFF}")
                continue
            hint = _rva_to_offset(sections, value)
            if hint is None:
                continue
            function = _cstring(data, hint + 2)
            if function:
                names.append(f"{dll}!{function}")
    return names


def _cstring(data: bytes, offset: int | None, limit: int = 256) -> str:
    if offset is None or offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, offset + limit)
    if end == -1:
        end = min(offset + limit, len(data))
    return data[offset:end].decode("latin-1", errors="replace")


def _overlay_offset(sections: list[dict]) -> int:
    return max((s["raw_pointer"] + s["raw_size"] for s in sections), default=0)


def parse(data: bytes, ident) -> tuple[list[Fact], list[str], list[str], list[tuple[str, bytes]]]:
    """Uniform extractor contract: (facts, imported symbols, structural notes, extra bodies).

    An executable image contributes no extra bodies — there is no embedded document to
    lift out — so the fourth element is always empty here. The shape is kept identical
    across every extractor so the pipeline never has to ask which one it called.
    """
    facts, imports, notes = _analyse(data, ident)
    return facts, imports, notes, []
