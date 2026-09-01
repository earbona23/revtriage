"""Minimal ELF reader: section headers, DT_NEEDED libraries, dynamic symbols.

Same reasoning as the PE reader — hand-written, bounded, partial on purpose. For Linux
triage the two questions that matter early are *what does it link against* (a stripped
binary that pulls in libcurl and libcrypto is telling you something) and *what dynamic
symbols does it call*, which is the ELF analogue of the PE import table.
"""

from __future__ import annotations

import struct

from ..model import Fact
from ..util import shannon_entropy

E_TYPES = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
MACHINES = {0x03: "i386", 0x28: "ARM", 0x3E: "x86-64", 0xB7: "AArch64", 0xF3: "RISC-V"}
DT_NEEDED = 1
DT_STRTAB = 5
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29


def _analyse(data: bytes, ident) -> tuple[list[Fact], list[str], list[str]]:
    facts: list[Fact] = []
    imports: list[str] = []
    notes: list[str] = []

    if len(data) < 64:
        return [Fact("elf.error", "truncated", "shorter than an ELF header")], [], []

    is64 = data[4] == 2
    endian = ">" if data[5] == 2 else "<"
    (e_type,) = struct.unpack_from(endian + "H", data, 16)
    (e_machine,) = struct.unpack_from(endian + "H", data, 18)
    facts.append(Fact("elf.type", E_TYPES.get(e_type, str(e_type))))
    facts.append(Fact("elf.machine", MACHINES.get(e_machine, f"0x{e_machine:04x}")))
    facts.append(Fact("elf.bits", 64 if is64 else 32))

    if is64:
        e_shoff, = struct.unpack_from(endian + "Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
    else:
        e_shoff, = struct.unpack_from(endian + "I", data, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)

    sections = _sections(data, endian, is64, e_shoff, e_shentsize, min(e_shnum, 256), e_shstrndx)
    facts.append(Fact("elf.section_count", len(sections)))

    if not sections:
        # Section headers stripped entirely. Legitimate for some static binaries, and
        # also the cheapest way to inconvenience an analyst.
        notes.append("elf:section-headers-stripped")
        facts.append(Fact("elf.section_headers", "absent", "no readable section headers"))

    by_name = {s["name"]: s for s in sections}
    for name in (".text", ".data", ".rodata"):
        section = by_name.get(name)
        if section and section["body"]:
            entropy = shannon_entropy(section["body"])
            facts.append(Fact(f"elf.section.{name}", {"size": section["size"], "entropy": round(entropy, 2)}))
            if name == ".text" and entropy >= 7.2:
                notes.append("elf:high-entropy-text")

    if ".symtab" not in by_name and ".debug_info" not in by_name:
        facts.append(Fact("elf.stripped", True, "no symbol table — the binary is stripped"))

    needed, symbols, dyn_notes = _dynamic(data, endian, is64, by_name)
    notes.extend(dyn_notes)
    if needed:
        facts.append(Fact("elf.needed_libraries", needed))
    imports = [f"{lib}" for lib in needed] + symbols
    if symbols:
        facts.append(Fact("elf.dynamic_symbol_count", len(symbols)))

    return facts, imports, notes


def _sections(data, endian, is64, shoff, shentsize, shnum, shstrndx) -> list[dict]:
    if not shoff or shoff >= len(data) or shentsize < (64 if is64 else 40):
        return []
    raw: list[dict] = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if base + shentsize > len(data):
            break
        if is64:
            name_off, sh_type = struct.unpack_from(endian + "II", data, base)
            offset, size = struct.unpack_from(endian + "QQ", data, base + 24)
            link, = struct.unpack_from(endian + "I", data, base + 40)
            entsize, = struct.unpack_from(endian + "Q", data, base + 56)
        else:
            name_off, sh_type = struct.unpack_from(endian + "II", data, base)
            offset, size = struct.unpack_from(endian + "II", data, base + 16)
            link, = struct.unpack_from(endian + "I", data, base + 24)
            entsize, = struct.unpack_from(endian + "I", data, base + 36)
        raw.append(
            {
                "name_off": name_off,
                "type": sh_type,
                "offset": offset,
                "size": size,
                "link": link,
                "entsize": entsize,
            }
        )

    strtab_offset = None
    if 0 <= shstrndx < len(raw):
        strtab_offset = raw[shstrndx]["offset"]

    sections: list[dict] = []
    for index, section in enumerate(raw):
        name = _string_at(data, strtab_offset, section["name_off"]) if strtab_offset is not None else f"sect{index}"
        body = b""
        # sh_type 8 is SHT_NOBITS: it occupies no file bytes, so its offset must not be
        # used to slice, or .bss would read whatever follows it on disk.
        if section["type"] != 8 and section["offset"] < len(data):
            body = data[section["offset"] : section["offset"] + min(section["size"], len(data) - section["offset"])]
        sections.append({**section, "name": name, "body": body, "index": index})
    return sections


def _dynamic(data, endian, is64, by_name) -> tuple[list[str], list[str], list[str]]:
    notes: list[str] = []
    dynamic = by_name.get(".dynamic")
    dynstr = by_name.get(".dynstr")
    needed: list[str] = []
    if dynamic and dynstr:
        step = 16 if is64 else 8
        fmt = endian + ("Qq" if is64 else "Ii")
        body = dynamic["body"]
        for offset in range(0, len(body) - step + 1, step):
            tag, value = struct.unpack_from(fmt, body, offset)
            if tag == 0:
                break
            if tag == DT_NEEDED:
                name = _string_at(data, dynstr["offset"], value)
                if name:
                    needed.append(name)
            elif tag in (DT_RPATH, DT_RUNPATH):
                path = _string_at(data, dynstr["offset"], value)
                if path:
                    # A writable or relative RPATH is a library-hijack primitive.
                    notes.append("elf:rpath-set")

    symbols: list[str] = []
    dynsym = by_name.get(".dynsym")
    if dynsym and dynstr and dynsym["entsize"]:
        entry_size = dynsym["entsize"]
        body = dynsym["body"]
        count = min(len(body) // entry_size, 8192)
        for index in range(count):
            base = index * entry_size
            if base + 4 > len(body):
                break
            (name_off,) = struct.unpack_from(endian + "I", body, base)
            name = _string_at(data, dynstr["offset"], name_off)
            if name:
                symbols.append(name)
    return needed, symbols, notes


def _string_at(data: bytes, table_offset: int | None, index: int, limit: int = 256) -> str:
    if table_offset is None:
        return ""
    start = table_offset + index
    if start < 0 or start >= len(data):
        return ""
    end = data.find(b"\x00", start, start + limit)
    if end == -1:
        end = min(start + limit, len(data))
    return data[start:end].decode("latin-1", errors="replace")


def parse(data: bytes, ident) -> tuple[list[Fact], list[str], list[str], list[tuple[str, bytes]]]:
    """Uniform extractor contract: (facts, imported symbols, structural notes, extra bodies).

    An executable image contributes no extra bodies — there is no embedded document to
    lift out — so the fourth element is always empty here. The shape is kept identical
    across every extractor so the pipeline never has to ask which one it called.
    """
    facts, imports, notes = _analyse(data, ident)
    return facts, imports, notes, []
