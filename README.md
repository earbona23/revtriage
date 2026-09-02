# revtriage

[![CI](https://github.com/earbona23/revtriage/actions/workflows/ci.yml/badge.svg)](https://github.com/earbona23/revtriage/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB)](https://www.python.org/downloads/)
[![Licence: MIT](https://img.shields.io/badge/Licence-MIT-blue.svg)](LICENSE)
[![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20deps-0-2f855a)](#zero-dependencies-is-a-security-property)
[![Mutation tested](https://img.shields.io/badge/mutation-17%2F17%20killed-2f855a)](#mutation-testing-break-it-on-purpose)
[![Offline](https://img.shields.io/badge/network-never-0f6e6e)](#what-it-refuses-to-do)

**Offline reverse-engineering triage.** Point it at a suspicious file — a PE, an ELF, a
Mach-O, an Office document, a `.ps1`/`.js`/`.vbs`, an archive — and it extracts
capabilities and indicators, peels the obfuscation layers one at a time, computes a score
you can argue with line by line, and writes a human report plus a validated **STIX 2.1**
bundle.

It **never uploads anything** and it **never executes the sample**. Analysis is parsing
and pattern matching over bytes, and nothing else.

```console
$ revtriage suspicious.ps1
```
```
# revtriage report — `suspicious.ps1`

## Verdict: **MALICIOUS**  (CRITICAL)
**Threat score: 61 / 100**
[############........] 61/100

| Contribution                                          | Points | Why                                        |
|-------------------------------------------------------|-------:|--------------------------------------------|
| Command and control                                   |     13 | 2 match(es) via c2.download, c2.web        |
| Persistence                                           |      8 | 1 match(es) via persist.run-key            |
| Obfuscation                                           |      7 | 2 match(es) via obf.encoded-payload        |
| Execution                                             |      6 | 3 match(es) via exec.powershell            |
| Anti-analysis                                         |      5 | 1 match(es) via anti.timing                |
| Lethal combination: persistence + command-and-control |     10 | survives reboot and calls out — an implant |
| Lethal combination: execution + command-and-control   |      6 | runs code fetched from somewhere else      |
| Lethal combination: obfuscation + execution           |      6 | hides the command it is about to run       |
```

Sixty-one is not a probability of guilt. It is eight statements, each of which names the
rule that produced it, and any one of which you can disagree with specifically.

> Analyses malware. Does not produce it. Every bundled sample is inert and synthetic
> (read `fixtures/build.py`), no binaries are committed, and every indicator in this repo
> points at an RFC 2606 sinkhole.

---

## Contents

- [The problem this solves](#the-problem-this-solves)
- [When you would actually reach for this](#when-you-would-actually-reach-for-this)
- [The Active Defense Trilogy](#the-active-defense-trilogy)
- [Five minutes, no samples of your own](#five-minutes-no-samples-of-your-own)
- [Provenance: the indicator that only exists after three decodes](#provenance-the-indicator-that-only-exists-after-three-decodes)
- [The capability graph](#the-capability-graph)
- [What it reads](#what-it-reads)
- [What it refuses to do](#what-it-refuses-to-do)
- [Zero dependencies is a security property](#zero-dependencies-is-a-security-property)
- [Free vs PRO](#free-vs-pro)
- [Tests, and the ones that exist because a mutant survived](#tests-and-the-ones-that-exist-because-a-mutant-survived)
- [Limitations](#limitations)
- [Install and use](#install-and-use)
- [Support the project](#support-the-project)

---

## The problem this solves

Something landed on a workstation. The sandbox queue is forty minutes deep, the vendor
verdict is `Trojan.Generic.31337`, and the question on the bridge call is not *what family
is this* — it is:

> **Does this thing persist, does it call out, and do I have to wake anyone up?**

That question has an answer that can be read off the bytes in under a second, and does not
require detonating anything, uploading anything, or telling the author of the sample that
they have been caught. `revtriage` answers exactly that, and shows its work.

It is a triage tool, deliberately. It will not name a family, it will not unpack a
commercial protector, and it does not pretend to replace a sandbox or an analyst. It
decides **what a human looks at first**, and it is honest about what it could not see.

## When you would actually reach for this

**The sandbox queue is forty minutes deep and the bridge call is now.** You need to know
whether this thing persists and calls out, not what family it belongs to. That answer is
in the bytes and takes under a second.

**You cannot upload it.** This is the case people underestimate. Uploading a targeted
sample to a public multi-scanner tells the author it landed and that someone is looking —
retrieval hashes are searchable, and more than one intrusion has been burned that way.
Worse, an attachment sent to your legal or HR team *is client data*, and pushing it to a
third party is a disclosure with your name on it. `revtriage` never opens a socket, so
neither of those decisions is ever on the table.

**Air-gapped, classified, or regulated environments** where nothing leaves the network and
"install these forty dependencies" is not an option. `pip install`, zero third-party
packages, done.

**Two hundred attachments from one phishing wave.** Loop the CLI, sort by score, read the
top ten. The other hundred and ninety come with a report explaining why they scored low,
which is the part that lets you defend the decision not to look at them.

**As a CI gate.** `--exit-code` makes the verdict the process exit status, so a build can
refuse an artefact, an upload endpoint can quarantine a file, and a pipeline can fail on a
dropped payload without a human in the loop.

**Feeding a TIP or a SIEM.** The STIX 2.1 bundle imports into MISP, OpenCTI or Sentinel
with the indicators, the ATT&CK techniques and the provenance intact. The JSON contract is
stable, so a wrapper script written once keeps working.

**Teaching, and interviews.** Every score is eight statements you can argue with, and the
layer table shows exactly where a C2 URL was hiding. It is a much better artefact for
explaining *why* a file is bad than a vendor verdict of `Trojan.Generic.31337`.

**When it is the wrong tool:** the sample is packed by a commercial protector (you will get
high entropy, a tiny import table, and a note saying so — that is a signal, not analysis),
you need runtime behaviour (that is a sandbox, permanently out of scope), or you need
family attribution. This decides what a human looks at first. It does not decide guilt.

## The Active Defense Trilogy

Three tools, one idea: an intruder who is already inside leaves traces that a
vulnerability scan will never find.

| Stage | Tool | Question it answers |
|---|---|---|
| **Detect** | [entra-tripwire](https://github.com/earbona23/entra-tripwire) | Is someone in here right now? |
| **Analyse** | **revtriage** *(this repo)* | This file they dropped — what can it do, and how bad is it? |
| **Contain** | [containment-cut](https://github.com/earbona23/containment-cut) | What is the cheapest cut that stops them without stopping the business? |

Each stands alone. Together they are the loop: an alert hands you a file, `revtriage`
turns the file into a verdict, an ATT&CK map and a STIX bundle, and the third computes
what to switch off. All three are offline-first and dependency-light for the same reason —
incident tooling must not widen the attack surface it was brought in to shrink.

## Five minutes, no samples of your own

No binaries are committed. You generate an inert corpus from a generator you can read,
then triage it:

```console
$ git clone https://github.com/earbona23/revtriage && cd revtriage
$ pip install -e .                      # no runtime dependencies
$ python fixtures/build.py              # writes 8 synthetic, inert samples
$ revtriage fixtures/generated/powershell_dropper.ps1
```

The corpus is eight files, each one built to exercise a specific path:

| Sample | What it is there to prove |
|---|---|
| `powershell_dropper.ps1` | `-EncodedCommand` → one base64/UTF-16LE hop to an `IEX DownloadString`, a Run key and a sleep |
| `js_dropper.js` | `fromCharCode` obfuscation, `XMLHTTP` fetch, `eval` of the response |
| `gzip_b64_payload.txt` | two stacked layers: base64 → gzip → a script that disables Defender |
| `xor_config.bin` | single-byte XOR recovered from the DOS-stub anchor, revealing a C2 URL |
| `fake_injector.exe` | non-runnable PE32: injection/keylog APIs in `.text`, a high-entropy `.rsrc` |
| `remote_template.docx` | OOXML with an external `attachedTemplate` — template injection, no macro |
| `clr_loader.bin` | the only sample that fires the **extended (PRO)** rules — see [Free vs PRO](#free-vs-pro) |
| `benign_readme.txt` | the control. A tool that flags everything has told you nothing |

## Provenance: the indicator that only exists after three decodes

This is the part that pays for the tool. The dropper's C2 URL is not in the file. It
exists only after the `-EncodedCommand` blob is base64-decoded from UTF-16LE — and the
report says so, on the row:

```
| Type | Indicator                            | Layer | Context        |
|------|--------------------------------------|-------|----------------|
| url  | hxxp://malware[.]example/stage2[.]bin | L1    |                |
| domain | malware[.]example                  | L1    | host of a URL  |
```

```
| Layer | Depth | Technique      | From | Size | Preview                                    |
|-------|------:|----------------|------|-----:|--------------------------------------------|
| L0    |     0 | original       | —    |  647 | powershell.exe -nop -w hidden -EncodedComm…|
| L1    |     1 | powershell-enc | L0   |  224 | IEX (New-Object Net.WebClient).DownloadStr…|
```

`L1`, not `L0`. Every indicator carries the layer it surfaced in and the technique that
produced that layer, so an analyst can reproduce the decode instead of trusting it — and
so an indicator that came out of a *speculative* decode is visibly weaker than one sitting
in the file. Everything is defanged in the human report (`hxxp`, `[.]`) because a report
gets pasted into a chat window, and a chat window makes URLs clickable.

Layers are found breadth-first through base64, hex, percent and char-code encodings,
single-byte XOR, gzip/zlib/bzip2/xz, PowerShell `-EncodedCommand` and string mangling —
stacked, budgeted, and gated. Most candidate decodes are noise, and a report full of noise
is the outcome the obfuscation was aiming for, so a candidate only becomes a layer if it
carries a real marker, real structure, or **verifiably decompresses** — the gate opens a
compressed stream rather than trusting its magic bytes.

## The capability graph

Matches become **nodes**; the pairs that mean far more together than apart become
**edges**. The score and the picture are computed from the same object, so the number in
the report and the diagram in the report can never disagree.

```
        ┌──────────────────────┐        +10          ┌──────────────────────┐
        │     Persistence      │ ═══════════════════▶ │ Command and control  │
        │  T1547.001 (Run key) │  an implant, not a   │  T1071.001   T1105   │
        └──────────┬───────────┘  one-shot script     └──────────▲───────────┘
                   │                                        +6   │
        ┌──────────▼───────────┐        +6            ┌──────────┴───────────┐
        │     Obfuscation      │ ═══════════════════▶ │      Execution       │
        │  T1140 (decode)      │  hides the command   │  T1059.001 (PS)      │
        └──────────────────────┘                      └──────────────────────┘
```

Two rules keep the number honest:

**A capability is capped.** Each contributes the sum of its matched rule weights up to a
ceiling. Without the cap, a sample that trips one behaviour twenty ways outscores a
genuinely more dangerous one that does three distinct things. When a cap bites, the report
says so — the analyst should know the raw signal was stronger than the number admits.

**Weight is summed over distinct rules, not raw matches.** The same rule firing in three
layers is provenance for one behaviour, not triple the evidence.

Bands: **malicious ≥ 60**, **likely-malicious ≥ 30**, **suspicious ≥ 10**, else benign.
The full method, and the argument behind every number:
[`docs/scoring.md`](docs/scoring.md).

## What it reads

- **Identity by content, never by extension** — `invoice.pdf.exe` does not fool it; the
  extension is used only to break a genuine tie, and the report names the basis it used.
- **PE** — sections, imports, per-section entropy, overlay, resource shape.
- **ELF** — `DT_NEEDED`, dynamic symbols, segment layout.
- **Mach-O** — load commands, linked dylibs, fat binaries.
- **OLE and OOXML** — macro streams with **MS-OVBA decompression** of the VBA source,
  remote-template relationships, DDE.
- **Archives** — shape, member names, nesting, and the bodies inside them as new layers.
- **Strings** — ASCII and UTF-16, which is where a binary's wide-char URLs and API names
  live.

Detections are **70 core rules** across **13 capabilities**, mapped to a hand-curated
subset of MITRE ATT&CK: **70 distinct techniques**, plus **7 lethal combinations**. No
invented technique IDs — a test walks every rule and fails the build if one cites an ID
that is not in the catalogue.

## What it refuses to do

These are structural, not promises, and each one is asserted by a test.

- **It never executes the sample.** No `eval`, no `exec`, no `subprocess`, no dynamic
  import of decoded bytes. The sample is data from the first byte to the last.
- **It never opens a socket.** There is no HTTP client in the package to misuse. An
  offline tool that quietly resolves a hostname has told the sample's author that it is
  being analysed, and roughly where the analyst sits.
- **It never uploads.** No telemetry, no crash reporting, no "anonymous statistics".
- **The licence never phones home.** PRO is an Ed25519-signed token verified locally —
  no account, no activation server.
- **A gated feature reports `skipped` with its reason.** It never reads as "ran and found
  nothing", which is how a coverage gap becomes an all-clear.

## Zero dependencies is a security property

`dependencies = []` in `pyproject.toml`. Every import under `src/` is standard library —
verify it yourself with `grep -rE "^(import|from)" src/`. The PE, ELF, Mach-O, OLE and
OOXML parsers, the deobfuscator, the STIX writer and even the Ed25519 verifier are
implemented here.

For a tool people point at live malware, "there is nothing third-party to audit" is not a
bragging point, it is the threat model: **the supply chain is exactly one project.** The
pure-Python Ed25519 is checked against the RFC 8032 test vector *and* cross-checked
against `pyca/cryptography` in the test suite, so implementing it cost no assurance.

Security policy, and what counts as a vulnerability when the input is the attacker:
[`SECURITY.md`](SECURITY.md).

## Free vs PRO

| | Free (MIT) | PRO |
|---|:---:|:---:|
| Triage, identification, structural extraction | yes | yes |
| Layered deobfuscation with full provenance | yes | yes |
| Capability graph, explainable score, ATT&CK mapping | yes | yes |
| IOC extraction, defanged | yes | yes |
| Markdown / JSON / **STIX 2.1** reports | yes | yes |
| Extended rule tier (5 higher-fidelity detections) | — | yes |
| Self-contained HTML report | — | yes |
| Orchestrated sandbox detonation | — | [design only](docs/sandbox-design.md) |

**The extended rules are additive: they can add detail, and can never change a free-tier
verdict.** That is a fact of control flow — `analyze.py` freezes the score before an
extended match can exist — and it is measured rather than asserted:

```console
$ CLR=fixtures/generated/clr_loader.bin
$ COUNT='[.score.value, ([.capabilities[]]|flatten|length)]'

$ revtriage $CLR -f json | jq -c "$COUNT"
[18,4]                                    # free: score 18, four findings
$ REVTRIAGE_LICENSE=$TOKEN revtriage $CLR -f json | jq -c "$COUNT"
[18,10]                                   # PRO: same 18, ten findings
```

Six extra findings — ETW blinding, a named-pipe channel, in-memory CLR hosting — and the
same 18. Scored naively, that match set comes to **37**, which is a different verdict
band. `tests/test_analyze.py::test_the_score_freeze_is_load_bearing_not_a_coincidence`
asserts exactly that counterfactual, because the obvious test (*"the two scores are
equal"*) also passes when the extra findings happen to be worth nothing — and for a while,
it did. See [the mutation section](#mutation-testing-break-it-on-purpose).

PRO is unlocked by an offline token:

```console
$ export REVTRIAGE_LICENSE="<token>"     # or write it to ~/.config/revtriage/license
```

## Tests, and the ones that exist because a mutant survived

```console
$ pip install -e ".[dev]"
$ pytest
121 passed
```

CI runs the suite on **Ubuntu, Windows and macOS** across Python **3.11 / 3.12 / 3.13**,
plus a rule-catalogue integrity check and an end-to-end demo whose STIX output is fed
through the validator.

### Mutation testing: break it on purpose

A green suite proves the tests ran. It does not prove they would notice if the analyser
were wrong. `scripts/mutation_test.py` introduces one real defect at a time — in the
score, the graph, the keep-gate, the XOR recovery, the free/PRO boundary, the licence, the
STIX validator, the defanger and the offline guarantee itself — and demands the suite go
red.

```console
$ python scripts/mutation_test.py
17/17 mutants killed, 0 survived, 0 errors
```

It reports three outcomes, not two: `killed`, `SURVIVED` and `ERROR`. The third exists
because **a mutation that silently fails to apply looks exactly like a killed mutant** —
the suite passes either way, and the flattering reading is the wrong one. Every mutation
asserts its target text exists before the edit and that the bytes on disk moved after it.

Three mutants survived the first run. They are the reason these tests exist:

| Survivor | The hole it exposed |
|---|---|
| `analyze/pro-rules-move-the-verdict` | The free/PRO guarantee was **never exercised**: no bundled sample fired an extended rule, so the test asserting "the score does not move" compared two identical empty sets. Fixed by adding `clr_loader.bin` and asserting the counterfactual. |
| `stix/validator-is-a-rubber-stamp` | The validator test asserted only that the problem list was *non-empty*. The bundle had two defects, so deleting one check kept it green. Each invariant is now broken on its own and matched by the message it produces. |
| `deob/compressed-check-is-a-rubber-stamp` | Nothing tested that "this decodes as compressed" actually opens the stream. Awarding that bonus on the magic bytes alone turns any noise starting `1f 8b` into a layer. |

Two more things this run found the hard way, both worth stealing:

**A flaky test is worse than no test.** `test_pure_noise_is_rejected` drew 2 KB from
`os.urandom`, and two random bytes land on `\\` — a marker worth 40 points on its own —
about three times in a hundred draws. Across a nine-job matrix that is a red build on
roughly a quarter of pushes, and it would have been blamed on the runner every time. The
buffer is seeded now, and the test asserts its own premise.

**A restored mutant can survive in the bytecode.** Restoring a mutant rewrites the file
with content of the *same length*; CPython invalidates a `.pyc` on the source's
`(mtime, size)`, both of which can be unchanged if the restore lands in the same clock
second as the compile. The interpreter then reuses bytecode compiled from the mutated
source — a **false kill**, with the defect still executing while the tree looks clean. The
harness now clears every `__pycache__` and runs the suite with `-B`.

## Limitations

Stated plainly, because a triage tool that oversells its coverage is worse than one that
does not exist.

- **It is a triage prior, not a verdict.** The score decides what a human reads first. It
  is calibrated by argument in `docs/scoring.md`, not against a labelled corpus, and there
  is no claimed false-positive rate because there is no dataset behind one.
- **Packers and protectors win.** A UPX-style packer, a commercial protector or a .NET
  obfuscator will hide the strings this depends on. You will see high entropy, a small
  import table and a note saying so — which is itself a signal, but it is not analysis.
- **No emulation, no disassembly.** Control flow is not followed. A capability expressed
  only in machine code, with no string or import to betray it, is invisible here.
- **Deobfuscation is budgeted and breadth-first.** Deeply nested or custom multi-byte
  schemes are out of reach by design; the alternative is a tool that hangs on hostile
  input.
- **Single-byte XOR only**, and only when an anchor confirms the key — an unanchored key
  is a guess, and a guess presented as a recovered key is worse than nothing.
- **The ATT&CK subset is hand-curated and pinned.** It is not the full matrix and does not
  auto-update. Provenance is recorded; the canonical data is at <https://attack.mitre.org/>.
- **Archives are read, not fully unpacked.** Encrypted archives are identified and left
  alone.
- **Nothing here is a sandbox.** Runtime behaviour — what it actually does when executed —
  is out of scope, permanently and on purpose.

## Install and use

```console
$ pip install -e .                              # editable, from a checkout
$ revtriage --help
$ revtriage suspicious.bin                      # Markdown to stdout
$ revtriage suspicious.bin -f json -o triage.json
$ revtriage suspicious.bin -f stix -o triage.stix.json
$ revtriage suspicious.bin -f all -o triage     # .md, .json and .stix.json
$ revtriage suspicious.bin --exit-code          # exit code carries the verdict
```

Exit codes, because this belongs in a pipeline:

| code | meaning |
|---|---|
| `0` | benign, or (without `--exit-code`) the analysis completed |
| `10` / `20` / `30` | with `--exit-code`: suspicious / likely-malicious / malicious |
| `2` | the file could not be read |

Requires Python ≥ 3.11. Nothing else.

How the pipeline is put together, stage by stage, and why the order is what it is:
[`docs/architecture.md`](docs/architecture.md).

## Support the project

revtriage is **open-core**: the triage engine is MIT and free forever. Nothing that
decides a verdict is behind the licence.

- **[GitHub Sponsors](https://github.com/sponsors/earbona23)** — any amount.
- **PRO licences** — from US$29/mo per org (US$290/yr), all seats. Email earbona@arrankago.com · [pricing](docs/PRO.md#pricing).

## More tools like this

Part of a small suite of dependency-free security tools I maintain. Each one runs
offline, ships its own tests, and maps its detections to MITRE ATT&CK.

- **[vantage](https://github.com/earbona23/vantage)** — see your domain's external attack surface the way an attacker's first recon does, scored and explained.
- **[entraform](https://github.com/earbona23/entraform)** — catch risky Entra/Azure changes in a Terraform plan, before apply.
- **[entra-tripwire](https://github.com/earbona23/entra-tripwire)** — decoy identities in Entra ID that fire the moment someone touches them.
- **[containment-cut](https://github.com/earbona23/containment-cut)** — the minimum-cost set of actions that provably severs a compromised identity, with a proof.

## Licence

MIT — see [`LICENSE`](LICENSE).

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. This project is not
affiliated with or endorsed by MITRE; technique identifiers are reproduced for
interoperability. Canonical data: <https://attack.mitre.org/>.
