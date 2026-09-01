"""Structural extraction: turn a file format into facts, symbols and embedded bodies.

Each extractor is deliberately partial. A triage tool has to survive the file it was
handed — truncated, padded, deliberately corrupted — so every parser returns what it
managed to read and appends a note about what it could not, instead of raising. An
exception here would mean the analyst gets nothing; a partial parse means they get the
sections that did decode *plus* an explicit "the import table is malformed", which is
itself a finding.

Every extractor returns the same four things:

* ``facts``   — structural observations for the report.
* ``imports`` — imported/linked symbol names, matched by capability rules.
* ``notes``   — short structural tags (``pe:high-entropy-section``) that rules and the
  scorer consume. They exist so a rule can fire on *shape*, not only on strings.
* ``bodies``  — embedded content that deserves its own analysis layer (macro source, a
  script inside an archive).
"""

from __future__ import annotations

from ..identify import (
    KIND_ELF,
    KIND_JAR,
    KIND_MACHO,
    KIND_OLE,
    KIND_OOXML,
    KIND_PE,
    KIND_ZIP,
    Identification,
)
from ..model import Fact
from . import archive, elf, macho, office, pe
from .strings import extract_strings

__all__ = ["extract_structure", "extract_strings", "Fact"]

_EXTRACTORS = {
    KIND_PE: pe.parse,
    KIND_ELF: elf.parse,
    KIND_MACHO: macho.parse,
    KIND_OOXML: office.parse,
    KIND_OLE: office.parse,
    KIND_JAR: archive.parse,
    KIND_ZIP: archive.parse,
}


def extract_structure(
    data: bytes, ident: Identification
) -> tuple[list[Fact], list[str], list[str], list[tuple[str, bytes]]]:
    """Run the extractor for the identified type, or return empty results for plain text."""
    extractor = _EXTRACTORS.get(ident.kind)
    if extractor is None:
        return [], [], [], []
    try:
        return extractor(data, ident)
    except Exception as exc:  # noqa: BLE001 - a hostile file must not abort the triage
        # Deliberately broad. The alternative is a stack trace instead of a report, and
        # crashing the parser is itself a well-known anti-analysis technique — so a
        # parser failure is recorded as a finding rather than allowed to end the run.
        return (
            [Fact("extract.error", type(exc).__name__, str(exc)[:200])],
            [],
            [f"extract:parser-failed:{ident.kind}"],
            [],
        )
