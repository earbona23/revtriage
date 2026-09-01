# revtriage

**Offline reverse-engineering triage.** Point it at a suspicious file — a PE, ELF, Mach-O,
an Office document with macros, a `.ps1`/`.js`/`.vbs`, an archive — and it extracts
capabilities and IOCs, peels the common obfuscation layers, computes an **explainable**
threat score, and emits a human report plus a **STIX 2.1** bundle.

It **never uploads anything**, and it **never executes the sample**. Analysis is pure
parsing and pattern matching over bytes. That is the whole point: the file is hostile, so
the tool that reads it has **zero third-party runtime dependencies** — the entire supply
chain is this one project. Even the Ed25519 licence verifier is implemented on the Python
standard library alone.

> Analyses malware. Does not produce it. Every bundled sample is inert and synthetic (see
> `fixtures/build.py`), and every indicator in this repo points at an RFC-2606 sinkhole.

---

## The Active Defense Trilogy

revtriage is the middle link in a three-tool defensive chain — **detect, analyse,
contain** — each usable alone, better together:

| Stage | Tool | Question it answers |
|---|---|---|
| 🔎 **Detect** | [`entra-tripwire`](https://github.com/earbona23/entra-tripwire) | *Did something suspicious just happen in my identity plane?* |
| 🧪 **Analyse** | **`revtriage`** (this repo) | *This file it dropped — what can it do, and how bad is it?* |
| ⛓️ **Contain** | [`containment-cut`](https://github.com/earbona23/containment-cut) | *Cut it off — revoke, isolate, and stop the spread.* |

An alert from **detect** hands you a file; **revtriage** turns that file into a verdict,
an ATT&CK map and a STIX bundle; **contain** acts on it. All three are offline-first and
dependency-light for the same reason: incident tooling should not itself widen the attack
surface.

---

## Quickstart (offline demo)

No binaries are committed — you generate the inert corpus, then triage it:

```console
$ pip install -e .
$ python fixtures/build.py                       # writes synthetic, inert samples
$ revtriage fixtures/generated/powershell_dropper.ps1
```

Real output (trimmed):

```
# revtriage report — `powershell_dropper.ps1`

## Verdict: **MALICIOUS**  (CRITICAL)
**Threat score: 61 / 100**
[############........] 61/100

## How the score was built
| Contribution | Points | Why |
|---|---:|---|
| Command and control | 13 | 2 match(es) via c2.download, c2.web |
| Persistence | 8 | 1 match(es) via persist.run-key |
| Obfuscation | 7 | 2 match(es) via obf.encoded-payload |
| Execution | 6 | 3 match(es) via exec.powershell |
| Anti-analysis | 5 | 1 match(es) via anti.timing |
| Lethal combination: persistence + command-and-control | 10 | survives reboot and calls out — an implant |
| Lethal combination: execution + command-and-control  |  6 | runs code fetched from somewhere else |
| Lethal combination: obfuscation + execution          |  6 | hides the command it is about to run |
```

The `-EncodedCommand` was decoded to a new layer (`L1`), and the C2 URL was pulled **from
that decoded layer**, with the provenance recorded:

```
| url | hxxp://malware[.]example/stage2[.]bin | L1 | |   ← defanged; appeared only after base64/UTF-16LE decode
```

Other formats: `revtriage sample -f json`, `-f stix`, or `-f all -o report`.

---

## The capability graph

Matches are organised into a graph: **capabilities are nodes**, and the pairs that mean
far more together than apart are **edges** (a "lethal combination"). The score and the
picture are computed from the same object, so they can never disagree.

```
        ┌──────────────────────┐        +10        ┌──────────────────────┐
        │     Persistence      │ ═══════════════════▶│ Command and control  │
        │  T1547.001 (Run key) │  implant, not a     │  T1071.001  T1105    │
        └──────────┬───────────┘  one-shot script    └──────────▲───────────┘
                   │                                       +6    │
        ┌──────────▼───────────┐        +6           ┌──────────┴───────────┐
        │     Obfuscation      │ ═══════════════════▶│      Execution       │
        │  T1140 (decode)      │  hides the command  │  T1059.001 (PS)      │
        └──────────────────────┘                     └──────────────────────┘
```

The number is a **triage prior** — where a human should look first — not a probability of
guilt. Every point traces to a line in the report. Full method and thresholds:
[`docs/scoring.md`](docs/scoring.md).

---

## What it does

- **Identify by content, never extension** — `invoice.pdf.exe` doesn't fool it.
- **Structural extraction** — PE sections/imports/entropy/overlay, ELF `DT_NEEDED`/dynamic
  symbols, Mach-O load commands/dylibs, OLE/OOXML macros (with **MS-OVBA decompression**
  of the VBA source), remote-template & DDE, archive shape.
- **Layered deobfuscation** — base64/hex/percent/char-code, single-byte XOR (with
  verified compressed-container recovery), gzip/zlib/bzip2/xz, PowerShell `-EncodedCommand`
  and string mangling — stacked, breadth-first, budgeted, with **provenance** on every
  layer.
- **Capabilities → ATT&CK** — a hand-curated subset of MITRE ATT&CK (no invented IDs; a
  test enforces it) across 13 capabilities.
- **IOCs with provenance** — URLs, IPs, domains, emails, registry keys, paths — each tied
  to the layer it surfaced in, defanged for safe copy-paste.
- **Reports** — Markdown, JSON (a stable contract), and a **validated** STIX 2.1 bundle.

---

## Free vs PRO

| | Free (MIT) | PRO |
|---|:---:|:---:|
| Triage, identify, structural extraction | ✅ | ✅ |
| Layered deobfuscation + provenance | ✅ | ✅ |
| Capability graph + explainable score + ATT&CK | ✅ | ✅ |
| IOC extraction | ✅ | ✅ |
| Markdown / JSON / **STIX 2.1** reports | ✅ | ✅ |
| **Extended rule tier** (higher-fidelity detections) | — | ✅ |
| **Self-contained HTML report** | — | ✅ |
| **Orchestrated sandbox detonation** (design) | — | 🔒 [design](docs/sandbox-design.md) |

The PRO **extended rules are additive**: they are applied *after* the score is computed,
so they can add detail but **can never change a free-tier verdict**. That is a fact of
control flow (`analyze.py` freezes the core score first), proven by
`tests/test_analyze.py::test_pro_extended_rules_are_additive`. A gated feature always
reports `skipped` **with its reason** — it never masquerades as a feature that ran and
found nothing.

PRO is unlocked by an **offline Ed25519-signed licence token** (no phone-home):

```console
$ export REVTRIAGE_LICENSE="<token>"     # or ~/.config/revtriage/license
```

---

## Verification & quality

- **Zero runtime dependencies** — `dependencies = []` in `pyproject.toml`; every import in
  `src/` is from the standard library. Verify: `grep -rE "^(import|from)" src/`.
- **Standards-correct crypto** — the pure-stdlib Ed25519 is checked against the RFC 8032
  test vector *and* pyca/cryptography in `tests/test_license.py`.
- **Valid STIX 2.1** — `report/stix.py` ships a structural validator; a test runs it over
  every corpus sample.
- **Tests that mean it** — **89 tests, all green.** The scoring engine and the
  deobfuscator carry mutation-killing tests. A manual mutation pass flips one operator or
  threshold at a time and confirms a specific test goes red:

  | Mutation | Test that caught it | Result |
  |---|---|---|
  | `min(weight, cap)` → `max` | `test_cap_is_a_minimum_not_a_maximum` | 🔴 killed |
  | verdict band `>=` → `>` | `test_verdict_band_boundaries` | 🔴 killed |
  | drop lethal-combination bonus | `test_lethal_combination_adds_its_bonus` | 🔴 killed |
  | distinct-rule weight → per-match sum | `test_distinct_rule_weighting_ignores_duplicate_layers` | 🔴 killed |
  | XOR allow key `0x00` | `test_xor_never_reports_key_zero` | 🔴 killed |
  | keep-gate `>=` → `>` | `test_keep_threshold_boundary_is_inclusive` | 🔴 killed |

  **6 / 6 mutants killed.** None of the tests pass with the bug present — no `assert
  something > 0` theatre.

Run it yourself:

```console
$ pip install -e ".[dev]"
$ pytest
```

CI runs the suite on **Ubuntu, Windows and macOS** across Python **3.11 / 3.12 / 3.13**,
plus a rule-integrity check and an end-to-end demo whose STIX output is validated.

---

## Install & use

```console
$ pip install -e .            # editable, from a checkout
$ revtriage --help
$ revtriage suspicious.bin              # Markdown to stdout
$ revtriage suspicious.bin -f json -o triage.json
$ revtriage suspicious.bin -f all -o triage       # triage.md, triage.json, triage.stix.json
$ revtriage suspicious.bin --exit-code            # exit code carries the verdict (CI gate)
```

Requires Python ≥ 3.11. Nothing else.

---

## Support the project

revtriage is **open-core**: the triage engine is MIT and free forever. Sponsorship funds
the maintained ATT&CK rule catalogue and the PRO tier.

- **GitHub Sponsors** — see the *Sponsor* button on this repo.
- **Polar** — [polar.sh/earbona23](https://polar.sh/earbona23).

---

## License

MIT — see [`LICENSE`](LICENSE).

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. This project is not
affiliated with or endorsed by MITRE; technique identifiers are reproduced for
interoperability. Canonical data: <https://attack.mitre.org/>.
