"""Minimal Mach-O reader: load commands, linked dylibs, segment entropy.

Only the load-command table is walked. For triage that is where the useful signal is:
which dylibs the binary pulls in (Security.framework, libcurl), whether it is code-signed
at all (LC_CODE_SIGNATURE), and whether an encrypted segment is present (LC_ENCRYPTION_INFO,
which on a file that is not from the App Store is a strong packing signal).
"""

from __future__ import annotations

import struct

from ..model import Fact
from ..util import shannon_entropy

LC_SEGMENT = 0x01
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18
LC_ID_DYLIB = 0x0D
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

CPU_TYPES = {7: "i386", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64"}


def _analyse(data: bytes, ident) -> tuple[list[Fact], list[str], list[str]]:
    facts: list[Fact] = []
    imports: list[str] = []
    notes: list[str] = []

    if ident.details.get("slices"):
        facts.append(
            Fact(
                "macho.universal_slices",
                ident.details["slices"],
                "a fat binary — each slice would need its own pass; this triage reads the container only",
            )
        )
        return facts, imports, notes

    if len(data) < 32:
        return [Fact("macho.error", "truncated", "shorter than a Mach-O header")], [], []

    (magic,) = struct.unpack_from("<I", data, 0)
    is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    endian = ">" if magic in (0xCEFAEDFE, 0xCFFAEDFE) else "<"
    cputype, _sub, filetype, ncmds, _sizeofcmds, _flags = struct.unpack_from(endian + "iiIIII", data, 4)

    facts.append(Fact("macho.cpu", CPU_TYPES.get(cputype & 0xFFFFFFFF, str(cputype))))
    facts.append(Fact("macho.filetype", filetype))
    facts.append(Fact("macho.bits", 64 if is64 else 32))

    offset = 32 if is64 else 28
    signed = False
    for _ in range(min(ncmds, 512)):
        if offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            notes.append("macho:load-command-table-malformed")
            break

        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_ID_DYLIB):
            (name_offset,) = struct.unpack_from(endian + "I", data, offset + 8)
            name = _cstring(data, offset + name_offset, cmdsize)
            if name and cmd != LC_ID_DYLIB:
                imports.append(name)
        elif cmd == LC_CODE_SIGNATURE:
            signed = True
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            (cryptid,) = struct.unpack_from(endian + "I", data, offset + 20)
            if cryptid:
                facts.append(Fact("macho.encrypted_segment", True, "LC_ENCRYPTION_INFO with cryptid != 0"))
                notes.append("macho:encrypted-segment")
        elif cmd in (LC_SEGMENT, LC_SEGMENT_64):
            name = data[offset + 8 : offset + 24].rstrip(b"\x00").decode("latin-1", errors="replace")
            if is64:
                fileoff, filesize = struct.unpack_from(endian + "QQ", data, offset + 40)
            else:
                fileoff, filesize = struct.unpack_from(endian + "II", data, offset + 32)
            if filesize and fileoff < len(data):
                body = data[fileoff : fileoff + min(filesize, len(data) - fileoff)]
                entropy = shannon_entropy(body)
                facts.append(Fact(f"macho.segment.{name}", {"size": filesize, "entropy": round(entropy, 2)}))
                if name == "__TEXT" and entropy >= 7.2:
                    notes.append("macho:high-entropy-text")
        offset += cmdsize

    facts.append(Fact("macho.code_signature", signed, "LC_CODE_SIGNATURE present" if signed else "no code-signature load command"))
    if not signed:
        notes.append("macho:unsigned")
    if imports:
        facts.append(Fact("macho.linked_dylibs", imports))
    return facts, imports, notes


def _cstring(data: bytes, offset: int, limit: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, offset + limit)
    if end == -1:
        end = min(offset + limit, len(data))
    return data[offset:end].decode("latin-1", errors="replace")


def parse(data: bytes, ident) -> tuple[list[Fact], list[str], list[str], list[tuple[str, bytes]]]:
    """Uniform extractor contract: (facts, imported symbols, structural notes, extra bodies).

    An executable image contributes no extra bodies — there is no embedded document to
    lift out — so the fourth element is always empty here. The shape is kept identical
    across every extractor so the pipeline never has to ask which one it called.
    """
    facts, imports, notes = _analyse(data, ident)
    return facts, imports, notes, []
