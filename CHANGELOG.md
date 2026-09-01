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
- **Structural guarantees as tests** — `tests/test_guarantees.py` parses every module in
  `src/` and fails the build if anything imports a network or execution module, calls
  `eval`/`exec`/`os.system`, or pulls in a third-party package. The offline promise is
  checked, not asserted in prose.
- **Mutation harness** — `scripts/mutation_test.py` introduces 17 real defects one at a
  time and fails if the suite stays green, or if a mutation did not apply. Wired into CI.
- **Tests** — 121 tests including mutation-killers for the scoring engine, the
  deobfuscator, the licence and the STIX writer, plus a validator run over the whole
  corpus. CI on Ubuntu/Windows/macOS across Python 3.11–3.13.

### Fixed before release
- The free/PRO guarantee ("extended rules never change a free-tier verdict") was covered by
  a test that passed vacuously: no bundled sample fired an extended rule, so it compared two
  identical empty sets. Added the `clr_loader.bin` fixture, which does fire them, and a test
  asserting the counterfactual — scoring the PRO match set gives a different verdict band,
  so the freeze in `analyze.py` is demonstrably the only reason the number holds still.
- The STIX validator test asserted only that the problem list was non-empty. The sample
  bundle had two defects, so deleting either check kept it green. Each invariant is now
  broken on its own and matched by the message it produces.
- Nothing verified that the keep-gate's "this decodes as compressed" bonus actually opens
  the stream; awarding it on the magic bytes alone turns noise into a layer.
- `test_pure_noise_is_rejected` drew its buffer from `os.urandom`, and two random bytes
  land on a scoring marker roughly 3% of the time. Across the nine-job matrix that is a red
  build on about a quarter of pushes. The buffer is seeded and asserts its own premise.

[Unreleased]: https://github.com/earbona23/revtriage/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/earbona23/revtriage/releases/tag/v0.1.0
