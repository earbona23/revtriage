"""Office document extraction: macros, remote templates, DDE, embedded objects.

Covers both container generations, because attackers still use both:

* OOXML (`.docm`, `.xlsm`, and `.docx` with an injected relationship) — a ZIP. The VBA
  project, when present, is a whole OLE compound file stored as `word/vbaProject.bin`.
* Legacy OLE2 (`.doc`, `.xls`) — the compound file *is* the document.

The output that matters is the macro **source**, recovered and handed to the rest of the
pipeline as its own layer, so capability rules match on what the macro actually does
rather than on the mere fact that a macro exists.
"""

from __future__ import annotations

import io
import re
import zipfile

from ..model import Fact
from . import ole

_AUTO_EXEC = (
    "AutoOpen", "AutoClose", "AutoExec", "AutoNew", "Document_Open", "Document_Close",
    "DocumentOpen", "Workbook_Open", "Workbook_Activate", "Auto_Open", "Auto_Close",
)

_EXTERNAL_TARGET = re.compile(
    rb'Target="(?P<target>[^"]+)"[^>]*TargetMode="External"', re.IGNORECASE
)
_RELATIONSHIP_TYPE = re.compile(rb'Type="(?P<type>[^"]+)"')


def parse(data: bytes, ident) -> tuple[list[Fact], list[str], list[str], list[tuple[str, bytes]]]:
    if ident.kind == "ooxml":
        return _parse_ooxml(data)
    return _parse_ole(data)


# -- OOXML ---------------------------------------------------------------------------


def _parse_ooxml(data: bytes) -> tuple[list[Fact], list[str], list[str], list[tuple[str, bytes]]]:
    facts: list[Fact] = []
    notes: list[str] = []
    bodies: list[tuple[str, bytes]] = []

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        names = archive.namelist()
    except zipfile.BadZipFile:
        return [Fact("office.error", "unreadable", "the OOXML container is not a readable ZIP")], [], ["office:container-corrupt"], []

    facts.append(Fact("office.part_count", len(names)))

    vba_parts = [n for n in names if n.lower().endswith("vbaproject.bin")]
    if vba_parts:
        notes.append("office:has-vba-project")
        facts.append(Fact("office.vba_project", vba_parts))
        for part in vba_parts:
            try:
                project = archive.read(part)
            except (KeyError, zipfile.BadZipFile, RuntimeError) as exc:
                notes.append("office:vba-project-unreadable")
                facts.append(Fact("office.vba_project_error", str(exc)))
                continue
            module_facts, module_notes, module_bodies = _vba_modules(project)
            facts.extend(module_facts)
            notes.extend(module_notes)
            bodies.extend(module_bodies)

    if any(n.lower().startswith("xl/macrosheets/") for n in names):
        # Excel 4.0 macro sheets predate VBA and bypass a lot of macro tooling.
        notes.append("office:has-xlm-macrosheet")
        facts.append(Fact("office.excel4_macrosheet", True, "an Excel 4.0 (XLM) macro sheet is present"))

    externals = _external_relationships(archive, names)
    if externals:
        facts.append(Fact("office.external_relationships", externals))
        notes.append("office:external-relationship")
        if any(item["kind"] == "attachedTemplate" for item in externals):
            notes.append("office:remote-template")
        if any(item["kind"] in ("oleObject", "frame") for item in externals):
            notes.append("office:external-object")

    for part in ("word/document.xml", "xl/workbook.xml"):
        if part in names:
            try:
                body = archive.read(part)
            except (KeyError, RuntimeError):
                continue
            if re.search(rb"DDEAUTO|\bDDE\b", body, re.IGNORECASE):
                notes.append("office:dde-field")
                facts.append(Fact("office.dde_field", True, f"a DDE field is present in {part}"))

    return facts, [], notes, bodies


def _external_relationships(archive: zipfile.ZipFile, names: list[str]) -> list[dict]:
    found: list[dict] = []
    for name in names:
        if not name.lower().endswith(".rels"):
            continue
        try:
            body = archive.read(name)
        except (KeyError, RuntimeError):
            continue
        for chunk in body.split(b"<Relationship")[1:]:
            match = _EXTERNAL_TARGET.search(chunk)
            if not match:
                continue
            type_match = _RELATIONSHIP_TYPE.search(chunk)
            kind = "unknown"
            if type_match:
                kind = type_match.group("type").decode("latin-1").rsplit("/", 1)[-1]
            found.append(
                {
                    "part": name,
                    "kind": kind,
                    "target": match.group("target").decode("latin-1", errors="replace"),
                }
            )
    return found


# -- legacy OLE ----------------------------------------------------------------------


def _parse_ole(data: bytes) -> tuple[list[Fact], list[str], list[str], list[tuple[str, bytes]]]:
    facts: list[Fact] = []
    notes: list[str] = []
    bodies: list[tuple[str, bytes]] = []

    try:
        container = ole.OleFile(data)
    except ValueError as exc:
        return [Fact("office.error", str(exc))], [], ["office:container-corrupt"], []

    paths = [entry.path for entry in container.streams()]
    facts.append(Fact("office.ole_streams", paths[:64], f"{len(paths)} stream(s) in the compound file"))
    notes.extend(container.notes)

    lowered = [p.lower() for p in paths]
    if "worddocument" in lowered:
        facts.append(Fact("office.application", "Word"))
    elif "workbook" in lowered or "book" in lowered:
        facts.append(Fact("office.application", "Excel"))

    if any("vba" in p for p in lowered) or any("macros" in p for p in lowered):
        notes.append("office:has-vba-project")
        module_facts, module_notes, module_bodies = _vba_modules(data, container=container)
        facts.extend(module_facts)
        notes.extend(module_notes)
        bodies.extend(module_bodies)

    if any("ole10native" in p for p in lowered):
        notes.append("office:embedded-object")
        facts.append(Fact("office.embedded_object", True, "an Ole10Native stream carries an embedded file"))

    return facts, [], notes, bodies


# -- shared --------------------------------------------------------------------------


def _vba_modules(
    project: bytes, container: ole.OleFile | None = None
) -> tuple[list[Fact], list[str], list[tuple[str, bytes]]]:
    facts: list[Fact] = []
    notes: list[str] = []
    bodies: list[tuple[str, bytes]] = []

    if container is None:
        try:
            container = ole.OleFile(project)
        except ValueError:
            return [Fact("office.vba_project_error", "the VBA project is not a compound file")], ["office:vba-project-unreadable"], []

    recovered = 0
    for entry in container.streams():
        lower = entry.path.lower()
        if lower.endswith(("/dir", "/project", "/projectwm")) or "\x01" in entry.name:
            continue
        if "vba" not in lower and "macros" not in lower:
            continue
        try:
            stream = container.read(entry)
        except (IndexError, ValueError):
            continue
        source = ole.find_vba_source(stream)
        if not source:
            continue
        recovered += 1
        bodies.append((f"vba:{entry.path}", source.encode("utf-8", errors="replace")))
        triggers = [name for name in _AUTO_EXEC if name.lower() in source.lower()]
        if triggers:
            notes.append("office:macro-auto-execute")
            facts.append(
                Fact(
                    f"office.macro.{entry.name}.auto_exec",
                    triggers,
                    "runs on open, with no further user interaction beyond enabling content",
                )
            )

    if recovered:
        facts.append(Fact("office.vba_modules_recovered", recovered))
    else:
        notes.append("office:vba-source-not-recovered")
        facts.append(
            Fact(
                "office.vba_modules_recovered",
                0,
                "a VBA project is present but no module decompressed — treat the 'no macro code' result as unknown, not as clean",
            )
        )
    return facts, notes, bodies
