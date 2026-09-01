# Changelog

All notable changes to revtriage are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-09-01

First public release. Offline reverse-engineering triage with a capability graph, an
explainable threat score, IOC extraction, and STIX 2.1 output — zero runtime dependencies.

### Added
- **Identification** by content (magic bytes), never by extension, for PE, ELF, Mach-O,
  OLE2, OOXML, ZIP/JAR, PDF, RTF, gzip, and textual script dialects.
- **Structural extraction** — hand-written, bounded readers for PE (sections, imports,
  entropy, overlay), ELF (`DT_NEEDED`, dynamic symbols), Mach-O (load commands, dylibs,
  encryption), OLE/OOXML (macros with MS-OVBA decompression, remote templates, DDE), and
  archives (shape, nested archives, JAR manifests).
- **Layered deobfuscation** — base64/hex/percent/char-code, single-byte XOR with verified
  compressed-container recovery, gzip/zlib/bzip2/xz, and PowerShell `-EncodedCommand` /
  string mangling — stacked breadth-first, budgeted, with full provenance per layer.
- **Capability layer** — a hand-curated MITRE ATT&CK subset (72 techniques, 13
  capabilities), a rule engine mapping evidence to capabilities and techniques, and a
  capability graph with weighted "lethal combination" edges.
- **Explainable scoring** — capped per-capability contributions plus lethal-combination
  bonuses, mapped to a documented verdict band. Every point traces to the report.
- **IOC extraction** — URLs, IPv4, domains, emails, registry keys and paths, deduplicated
  with per-layer provenance and display defanging.
- **Reports** — Markdown, JSON (stable contract), and a structurally validated STIX 2.1
  bundle.
- **Offline licensing** — a pure-standard-library Ed25519 (RFC 8032) verifier, a
  JWT-shaped-but-not-JWT signed token format, and honest feature gating.
- **CLI** `revtriage`, the fixture generator `fixtures/build.py`, and the offline license
  minter `scripts/mint_license.py`.
- **Tests** — 89 tests including mutation-killers for the scoring engine and the
  deobfuscator, plus a STIX validator run over the whole corpus. CI on Ubuntu/Windows/macOS
  across Python 3.11–3.13.

[Unreleased]: https://github.com/earbona23/revtriage/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/earbona23/revtriage/releases/tag/v0.1.0
