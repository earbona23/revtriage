"""Identification and structural extraction over the synthetic corpus."""

from __future__ import annotations

from revtriage.extract import extract_strings, extract_structure
from revtriage.identify import identify


def test_identifies_pe(corpus):
    ident = identify(corpus["fake_injector.exe"], "fake_injector.exe")
    assert ident.kind == "pe"
    assert ident.basis == "magic"


def test_identifies_ooxml_document(corpus):
    ident = identify(corpus["remote_template.docx"], "remote_template.docx")
    assert ident.kind == "ooxml"


def test_identifies_powershell_by_content_not_extension():
    # A lying extension (.pdf) must not fool identification: the content decides.
    script = b"$client = New-Object System.Net.WebClient\nInvoke-Expression $client\n"
    ident = identify(script, "invoice.pdf")
    assert ident.kind == "script"
    assert ident.dialect == "powershell"


def test_extension_only_breaks_a_genuine_tie():
    ident = identify(b"just some words with no language markers at all here\n", "thing.vbs")
    assert ident.basis == "extension"
    assert ident.dialect == "vbscript"


def test_strings_extracts_ascii_and_utf16():
    # \xff separates the two runs unambiguously (it is neither printable ASCII nor a
    # valid UTF-16LE trailing byte here), so neither run bleeds into the other.
    data = b"ascii_marker_string\xff\xff" + "wide_marker_string".encode("utf-16-le")
    strings = extract_strings(data)
    assert "ascii_marker_string" in strings
    assert "wide_marker_string" in strings


def test_pe_extraction_finds_high_entropy_section(corpus):
    ident = identify(corpus["fake_injector.exe"], "fake_injector.exe")
    facts, imports, notes, bodies = extract_structure(corpus["fake_injector.exe"], ident)
    assert "pe:high-entropy-section" in notes


def test_ooxml_extraction_finds_remote_template(corpus):
    ident = identify(corpus["remote_template.docx"], "remote_template.docx")
    facts, imports, notes, bodies = extract_structure(corpus["remote_template.docx"], ident)
    assert "office:remote-template" in notes


def test_extractor_survives_a_corrupt_container():
    # A file that claims to be a ZIP but is truncated must not raise; it yields a finding.
    broken = b"PK\x03\x04" + b"\x00" * 8 + b"garbage"
    ident = identify(broken)
    facts, imports, notes, bodies = extract_structure(broken, ident)
    assert isinstance(notes, list)  # returned, did not throw
