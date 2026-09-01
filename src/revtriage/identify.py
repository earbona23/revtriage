"""File-type identification by content, never by extension.

Why this matters for triage: the single most common way a sample lies to an analyst is
its name. `invoice.pdf.exe`, a `.txt` that is really a PE, a `.jpg` that is really a JAR.
Everything downstream (which parser runs, which capability rules apply) branches on the
answer here, so the answer is taken from the bytes.

The extension is still read, but only as a *tiebreaker between text dialects* — a plain
UTF-8 script has no magic number, so there is nothing else to go on — and when it is used
the identification records that fact, so a report never implies more certainty than the
evidence supports.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

# Container kinds carry structure we can parse further.
KIND_PE = "pe"
KIND_ELF = "elf"
KIND_MACHO = "macho"
KIND_OOXML = "ooxml"
KIND_OLE = "ole"
KIND_JAR = "jar"
KIND_ZIP = "zip"
KIND_PDF = "pdf"
KIND_RTF = "rtf"
KIND_GZIP = "gzip"
KIND_SCRIPT = "script"
KIND_TEXT = "text"
KIND_DATA = "data"


@dataclass(frozen=True)
class Identification:
    """What the bytes say this file is."""

    kind: str
    label: str
    evidence: str
    #: 'magic' when decided by a signature, 'content' by textual heuristics,
    #: 'extension' when only the name could break the tie.
    basis: str = "magic"
    #: Sub-dialect for scripts: powershell, javascript, vbscript, batch, shell, python.
    dialect: str | None = None
    details: dict = field(default_factory=dict)

    @property
    def is_executable_image(self) -> bool:
        return self.kind in (KIND_PE, KIND_ELF, KIND_MACHO)


_MACHO_MAGICS = {
    0xFEEDFACE: ("Mach-O", 32, "little"),
    0xFEEDFACF: ("Mach-O 64-bit", 64, "little"),
    0xCEFAEDFE: ("Mach-O", 32, "big"),
    0xCFFAEDFE: ("Mach-O 64-bit", 64, "big"),
}

# Textual dialect fingerprints. Each entry: (dialect, label, patterns, minimum hits).
# Two hits are required for a dialect that shares vocabulary with others, so that a
# single stray word does not decide the file type.
_SCRIPT_SIGNS: list[tuple[str, str, tuple[str, ...], int]] = [
    (
        "powershell",
        "PowerShell script",
        (
            r"\$\w+\s*=", r"\bparam\s*\(", r"\bfunction\s+\w+\s*\{",
            r"-[Ee]ncodedCommand\b", r"\bInvoke-\w+", r"\bNew-Object\b",
            r"\[System\.\w+", r"\bWrite-(Host|Output)\b", r"\bSet-\w+\b",
        ),
        2,
    ),
    (
        "vbscript",
        "VBScript",
        (
            r"\bDim\s+\w+", r"\bSet\s+\w+\s*=\s*CreateObject", r"\bWScript\.\w+",
            r"\bEnd\s+(Sub|Function|If)\b", r"\bOn\s+Error\s+Resume\s+Next\b",
            r"\bSub\s+\w+\s*\(", r"\bChr\s*\(", r"\bMsgBox\b",
        ),
        2,
    ),
    (
        "javascript",
        "JavaScript",
        (
            r"\b(var|let|const)\s+\w+\s*=", r"\bfunction\s*\w*\s*\(", r"=>\s*\{",
            r"\bnew\s+ActiveXObject\b", r"\beval\s*\(", r"\bString\.fromCharCode\b",
            r"\brequire\s*\(", r"\bdocument\.\w+",
        ),
        2,
    ),
    (
        "batch",
        "Windows batch script",
        (
            r"(?im)^\s*@echo\s+off\b", r"(?im)^\s*set\s+\w+=", r"(?im)^\s*goto\s+\w+",
            r"(?im)^\s*if\s+(not\s+)?exist\b", r"%~dp0",
        ),
        1,
    ),
    (
        "shell",
        "Shell script",
        (
            r"(?m)^#!/bin/(ba|z|)sh", r"(?m)^\s*export\s+\w+=", r"\$\(\w+", r"\bfi\b\s*$",
        ),
        2,
    ),
    (
        "python",
        "Python script",
        (r"(?m)^\s*import\s+\w+", r"(?m)^\s*from\s+\w+\s+import\b", r"(?m)^\s*def\s+\w+\s*\("),
        2,
    ),
]

_EXTENSION_DIALECT = {
    ".ps1": ("powershell", "PowerShell script"),
    ".psm1": ("powershell", "PowerShell module"),
    ".js": ("javascript", "JavaScript"),
    ".jse": ("javascript", "JavaScript"),
    ".vbs": ("vbscript", "VBScript"),
    ".vbe": ("vbscript", "VBScript"),
    ".wsf": ("javascript", "Windows Script File"),
    ".bat": ("batch", "Windows batch script"),
    ".cmd": ("batch", "Windows batch script"),
    ".sh": ("shell", "Shell script"),
    ".py": ("python", "Python script"),
    ".hta": ("javascript", "HTML application"),
}


def identify(data: bytes, name_hint: str | None = None) -> Identification:
    """Identify `data`. `name_hint` is consulted only when the bytes are ambiguous text."""
    if not data:
        return Identification(KIND_DATA, "empty file", "zero bytes", basis="magic")

    binary = _identify_binary(data)
    if binary is not None:
        return binary

    if _looks_textual(data):
        return _identify_text(data, name_hint)

    return Identification(
        KIND_DATA,
        "unknown binary data",
        "no known magic number and the bytes are not text",
        basis="magic",
    )


def _identify_binary(data: bytes) -> Identification | None:
    if data[:2] == b"MZ":
        return _identify_mz(data)

    if data[:4] == b"\x7fELF":
        return _identify_elf(data)

    if len(data) >= 4:
        (magic_le,) = struct.unpack_from("<I", data, 0)
        if magic_le in _MACHO_MAGICS:
            label, bits, endian = _MACHO_MAGICS[magic_le]
            return Identification(
                KIND_MACHO, label, f"Mach-O magic 0x{magic_le:08x}",
                details={"bits": bits, "endianness": endian},
            )
        if data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            # CAFEBABE is shared by Mach-O fat binaries and Java class files. The count
            # field disambiguates: a fat header holds a small architecture count, a class
            # file holds a major version number in the same place.
            (field2,) = struct.unpack_from(">I", data, 4)
            if field2 < 0x40:
                return Identification(
                    KIND_MACHO, "Mach-O universal (fat) binary",
                    f"fat magic with {field2} architecture slice(s)",
                    details={"slices": field2},
                )
            return Identification(KIND_DATA, "Java class file", "0xCAFEBABE with class-file version")

    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return Identification(
            KIND_OLE, "OLE2 compound file (legacy Office document)",
            "OLE compound-file magic",
        )

    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return _identify_zip(data)

    if data[:2] == b"\x1f\x8b":
        return Identification(KIND_GZIP, "gzip stream", "gzip magic 1f 8b")

    if data[:5] == b"%PDF-":
        return Identification(KIND_PDF, "PDF document", "%PDF- header")

    if data[:5] == b"{\\rtf":
        return Identification(KIND_RTF, "RTF document", "{\\rtf header")

    return None


def _identify_mz(data: bytes) -> Identification:
    """An MZ header may be a DOS stub in front of a PE, or a bare DOS executable."""
    if len(data) >= 0x40:
        (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
        if 0 < pe_offset < len(data) - 4 and data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            details: dict = {"pe_offset": pe_offset}
            label = "PE executable"
            if len(data) >= pe_offset + 24:
                (machine,) = struct.unpack_from("<H", data, pe_offset + 4)
                (characteristics,) = struct.unpack_from("<H", data, pe_offset + 22)
                details["machine"] = machine
                details["is_dll"] = bool(characteristics & 0x2000)
                if characteristics & 0x2000:
                    label = "PE dynamic library (DLL)"
                details["bits"] = 64 if machine in (0x8664, 0xAA64) else 32
            return Identification(KIND_PE, label, "MZ stub with a PE\\0\\0 signature", details=details)
    return Identification(KIND_DATA, "DOS MZ executable", "MZ magic without a PE signature")


def _identify_elf(data: bytes) -> Identification:
    details: dict = {}
    if len(data) >= 20:
        details["bits"] = 64 if data[4] == 2 else 32
        details["endianness"] = "big" if data[5] == 2 else "little"
        fmt = ">H" if data[5] == 2 else "<H"
        (e_type,) = struct.unpack_from(fmt, data, 16)
        details["e_type"] = e_type
        kindname = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core dump"}.get(
            e_type, "object"
        )
        return Identification(KIND_ELF, f"ELF {details['bits']}-bit {kindname}", "\\x7fELF magic", details=details)
    return Identification(KIND_ELF, "ELF object", "\\x7fELF magic", details=details)


def _identify_zip(data: bytes) -> Identification:
    """A ZIP is a container; what it *is* depends on the names inside it."""
    names = _zip_entry_names(data)
    lowered = [n.lower() for n in names]

    if any(n == "[content_types].xml" for n in lowered):
        part = "unknown"
        if any(n.startswith("word/") for n in lowered):
            part = "word"
        elif any(n.startswith("xl/") for n in lowered):
            part = "excel"
        elif any(n.startswith("ppt/") for n in lowered):
            part = "powerpoint"
        has_vba = any(n.endswith("vbaproject.bin") for n in lowered)
        label = f"OOXML {part} document" + (" with a VBA project" if has_vba else "")
        return Identification(
            KIND_OOXML, label, "ZIP containing [Content_Types].xml",
            details={"application": part, "has_vba_project": has_vba, "entries": names},
        )

    if any(n == "androidmanifest.xml" for n in lowered):
        return Identification(
            KIND_ZIP, "Android package (APK)", "ZIP containing AndroidManifest.xml",
            details={"entries": names},
        )

    if any(n == "meta-inf/manifest.mf" for n in lowered) or any(n.endswith(".class") for n in lowered):
        return Identification(
            KIND_JAR, "Java archive (JAR)", "ZIP containing a JAR manifest or .class entries",
            details={"entries": names},
        )

    return Identification(KIND_ZIP, "ZIP archive", "ZIP local-file magic", details={"entries": names})


def _zip_entry_names(data: bytes) -> list[str]:
    """Read entry names straight out of the local file headers.

    `zipfile` is avoided here on purpose: it validates the central directory, and a
    deliberately corrupt archive — a common anti-analysis trick, since many tools give up
    while the target application still opens it — would raise instead of telling us what
    is inside. Scanning local headers degrades gracefully.
    """
    names: list[str] = []
    offset = 0
    limit = len(data)
    while offset + 30 <= limit and len(names) < 4096:
        if data[offset : offset + 4] != b"PK\x03\x04":
            found = data.find(b"PK\x03\x04", offset + 1)
            if found == -1:
                break
            offset = found
            continue
        try:
            name_len, extra_len = struct.unpack_from("<HH", data, offset + 26)
            (compressed_size,) = struct.unpack_from("<I", data, offset + 18)
            (flags,) = struct.unpack_from("<H", data, offset + 6)
        except struct.error:
            break
        start = offset + 30
        raw_name = data[start : start + name_len]
        try:
            names.append(raw_name.decode("utf-8"))
        except UnicodeDecodeError:
            names.append(raw_name.decode("latin-1"))
        # Bit 3 means sizes live in a trailing data descriptor, so the header size is a
        # lie. Fall back to scanning for the next header rather than trusting it.
        if flags & 0x08 or compressed_size == 0:
            nxt = data.find(b"PK\x03\x04", start + name_len)
            if nxt == -1:
                break
            offset = nxt
        else:
            offset = start + name_len + extra_len + compressed_size
    return names


def _looks_textual(data: bytes) -> bool:
    """Text if a decode succeeds and control characters are rare."""
    sample = data[:8192]
    if b"\x00\x00" in sample[:512]:
        return False
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        try:
            text = sample.decode(encoding)
        except UnicodeDecodeError:
            continue
        control = sum(1 for ch in text if ord(ch) < 9 or 13 < ord(ch) < 32)
        if control / max(len(text), 1) < 0.02:
            return True
    return False


def decode_text(data: bytes) -> str:
    """Best-effort text of a file already known to be textual."""
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def _identify_text(data: bytes, name_hint: str | None) -> Identification:
    text = decode_text(data)

    if text.startswith("#!"):
        first = text.splitlines()[0]
        if "python" in first:
            return Identification(KIND_SCRIPT, "Python script", "shebang line", basis="content", dialect="python")
        if "node" in first:
            return Identification(KIND_SCRIPT, "JavaScript", "shebang line", basis="content", dialect="javascript")
        if "pwsh" in first or "powershell" in first:
            return Identification(KIND_SCRIPT, "PowerShell script", "shebang line", basis="content", dialect="powershell")
        return Identification(KIND_SCRIPT, "Shell script", "shebang line", basis="content", dialect="shell")

    scores: list[tuple[int, str, str]] = []
    for dialect, label, patterns, minimum in _SCRIPT_SIGNS:
        hits = sum(1 for pattern in patterns if re.search(pattern, text))
        if hits >= minimum:
            scores.append((hits, dialect, label))
    if scores:
        scores.sort(reverse=True)
        best_hits, dialect, label = scores[0]
        return Identification(
            KIND_SCRIPT, label, f"{best_hits} {dialect} language marker(s) in the text",
            basis="content", dialect=dialect,
        )

    if name_hint:
        suffix = _suffix(name_hint)
        if suffix in _EXTENSION_DIALECT:
            dialect, label = _EXTENSION_DIALECT[suffix]
            return Identification(
                KIND_SCRIPT, label,
                f"no language markers in the content; the '{suffix}' extension broke the tie",
                basis="extension", dialect=dialect,
            )

    return Identification(KIND_TEXT, "plain text", "decodes as text, no language markers", basis="content")


def _suffix(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    dot = name.rfind(".")
    return name[dot:].lower() if dot > 0 else ""
