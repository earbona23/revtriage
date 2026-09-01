# Architecture

revtriage is a straight pipeline. Bytes go in; a `Triage` object comes out; three
reporters render it. Nothing in the pipeline executes the sample or touches the network —
every stage is pure parsing and pattern matching over `bytes`.

```
              ┌─────────────┐
  file bytes ─▶│  identify   │  magic-bytes, never the extension
              └──────┬──────┘
                     ▼
              ┌─────────────┐
              │   extract   │  PE / ELF / Mach-O / OLE / OOXML / ZIP
              │  structure  │  → facts, imported symbols, structural notes, embedded bodies
              └──────┬──────┘
                     ▼
              ┌─────────────┐
              │   strings   │  ASCII + UTF-16LE
              └──────┬──────┘
                     ▼
              ┌─────────────┐
              │ deobfuscate │  breadth-first, budgeted; base64 / hex / XOR / gzip / PS-enc …
              │  (layers)   │  each layer keeps a parent pointer → provenance
              └──────┬──────┘
                     ▼
       ┌─────────────┴─────────────┐
       ▼                           ▼
┌─────────────┐            ┌─────────────┐
│    rules    │            │    IOCs     │  URLs, IPs, domains, registry, paths — per layer
│  (capabilities)          └─────────────┘
└──────┬──────┘
       ▼
┌─────────────┐    ┌─────────────┐
│    graph    │───▶│   scoring   │  capped per-capability + lethal combos → explainable score
└─────────────┘    └─────────────┘
       │
       ▼
┌───────────────────────────────────────────┐
│  report:  markdown  ·  json  ·  stix 2.1   │
└───────────────────────────────────────────┘
```

## Modules

| Path | Responsibility |
|---|---|
| `identify.py` | File-type identification by content. |
| `extract/` | Per-format structural readers (hand-written, bounded, partial-on-purpose). |
| `deobfuscate/` | Layered, budgeted decoding with a keep-gate and provenance. |
| `capabilities/attack.py` | Hand-curated ATT&CK subset + capability taxonomy + lethal pairs. |
| `capabilities/rules.py` | Evidence → capability + technique. Core (scored) and extended (PRO). |
| `capabilities/graph.py` | Matches → capability graph (nodes + lethal edges). |
| `scoring.py` | The explainable score. Reads the graph, applies caps and bonuses. |
| `iocs.py` | Indicator extraction with per-layer provenance. |
| `report/` | Markdown, JSON, STIX 2.1 renderers + a STIX structural validator. |
| `license/` | Offline Ed25519 (RFC 8032) verification, token format, gating. |
| `analyze.py` | The orchestrator; freezes the core score before PRO detail is added. |
| `cli.py` | The `revtriage` command. |

## Threat model of the tool itself

The input is hostile by definition, so:

- **No third-party runtime code.** The whole supply chain is this one project; there is
  no dependency to audit or to hide an evaluator in. Even the Ed25519 licence verifier is
  stdlib-only.
- **Every parser is bounded.** Attacker-controlled counts, sizes and offsets are clamped
  before they become loop bounds or allocation sizes. A crafted file yields a partial
  parse plus a "this was malformed" finding — never a crash, because crashing the parser
  is itself an anti-analysis technique.
- **Nothing is executed, decompressed unbounded, or sent anywhere.** Decompression uses
  bounded `max_length`; the deobfuscator has depth/layer/byte budgets; and "we stopped
  looking" is recorded distinctly from "there was nothing to find".
