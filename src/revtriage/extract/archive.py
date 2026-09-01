"""ZIP and JAR extraction.

The interesting facts about an archive are rarely in the payload: they are in the shape
of the archive. A JAR whose manifest names a `Main-Class` is meant to be run; an archive
whose only entry is a `.js` or a `.lnk` is a delivery wrapper; a nested archive is there
to defeat scanners that only look one level deep.
"""

from __future__ import annotations

import io
import re
import zipfile

from ..model import Fact

_EXECUTABLE_SUFFIXES = (
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".jar", ".apk",
)
_SCRIPT_SUFFIXES = (".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".wsf", ".lnk")
_ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".gz", ".cab", ".iso", ".img")

_MAIN_CLASS = re.compile(rb"Main-Class:\s*(?P<value>[^\r\n]+)")


def parse(data: bytes, ident) -> tuple[list[Fact], list[str], list[str], list[tuple[str, bytes]]]:
    facts: list[Fact] = []
    notes: list[str] = []
    bodies: list[tuple[str, bytes]] = []

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except zipfile.BadZipFile:
        # The identifier already found local file headers, so a central-directory
        # failure here is a finding in itself, not a dead end.
        return (
            [Fact("archive.error", "central directory unreadable")],
            [],
            ["archive:corrupt-central-directory"],
            [],
        )

    names = [info.filename for info in infos]
    facts.append(Fact("archive.entry_count", len(names)))
    facts.append(Fact("archive.entries", names[:64]))

    if any(info.flag_bits & 0x1 for info in infos):
        notes.append("archive:encrypted-entry")
        facts.append(
            Fact("archive.encrypted", True, "at least one entry is password-protected — content scanning cannot see inside")
        )

    lowered = [n.lower() for n in names]
    executables = [n for n in lowered if n.endswith(_EXECUTABLE_SUFFIXES)]
    scripts = [n for n in lowered if n.endswith(_SCRIPT_SUFFIXES)]
    nested = [n for n in lowered if n.endswith(_ARCHIVE_SUFFIXES)]

    if executables:
        notes.append("archive:contains-executable")
        facts.append(Fact("archive.executables", executables[:32]))
    if scripts:
        notes.append("archive:contains-script")
        facts.append(Fact("archive.scripts", scripts[:32]))
    if nested:
        notes.append("archive:nested-archive")
        facts.append(Fact("archive.nested_archives", nested[:32]))

    # A double extension only exists to be read by a human, and only ever misleads one.
    double = [n for n in lowered if re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.[a-z0-9]{2,4}$", n)]
    if double:
        notes.append("archive:double-extension")
        facts.append(Fact("archive.double_extension", double[:16]))

    if "meta-inf/manifest.mf" in lowered:
        try:
            manifest = archive.read(next(n for n in names if n.lower() == "meta-inf/manifest.mf"))
        except (KeyError, RuntimeError, StopIteration):
            manifest = b""
        match = _MAIN_CLASS.search(manifest)
        if match:
            facts.append(Fact("archive.main_class", match.group("value").decode("latin-1").strip()))
            notes.append("archive:jar-executable")
        bodies.append(("jar:META-INF/MANIFEST.MF", manifest))

    # Small text entries are worth their own layer: a dropper's whole payload is often a
    # 2 KB script sitting next to a decoy document.
    for info in infos:
        if info.file_size and info.file_size <= 65536 and info.filename.lower().endswith(_SCRIPT_SUFFIXES):
            try:
                bodies.append((f"archive:{info.filename}", archive.read(info)))
            except (RuntimeError, zipfile.BadZipFile, KeyError):
                notes.append("archive:entry-unreadable")

    return facts, [], notes, bodies
