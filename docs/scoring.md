# The revtriage threat score

The score is a **triage prior**, not a probability of maliciousness. It answers one
question: *of the files on my desk, which do I open first?* It is deliberately
conservative on the low end — revtriage decides where attention goes, it does not decide
guilt — and every point is traceable to a line in the report.

## How the number is built

The number is computed from the **capability graph** in three steps.

### 1. Per-capability contribution (capped)

Each capability that has at least one matching rule contributes the **sum of its distinct
rule weights**, capped at a per-capability ceiling.

- *Distinct* rules: the same rule firing in three deobfuscation layers is provenance for
  one behaviour, not three times the evidence. It counts once. (This also stops the
  original file and the extracted-strings pseudo-layer, which overlap heavily, from
  double-counting every string detection.)
- *Capped*: without a ceiling, a sample that trips one behaviour twenty different ways
  would outscore a genuinely more dangerous sample that does three distinct things. When
  a capability is capped, the report says so — the raw signal was even stronger than the
  number admits.

Ceilings (from `capabilities/attack.py`):

| Capability | Cap | | Capability | Cap |
|---|---:|---|---|---:|
| impact | 22 | | anti-analysis | 14 |
| injection | 20 | | privilege-escalation | 14 |
| credential-access | 20 | | execution | 12 |
| persistence | 18 | | obfuscation | 12 |
| command-and-control | 18 | | discovery | 8 |
| exfiltration | 18 | | collection | 14 |
| defense-evasion | 16 | | | |

### 2. Lethal-combination bonuses

Some pairs mean far more together than apart. Each present pair adds a bonus with a stated
rationale:

| Pair | Bonus | Why |
|---|---:|---|
| persistence + command-and-control | 10 | survives reboot and calls out — an implant, not a one-shot |
| credential-access + exfiltration | 12 | reads secrets and has a way to send them |
| injection + anti-analysis | 10 | injects into other processes and resists inspection |
| collection + exfiltration | 8 | gathers local data and has a way to send it |
| impact + discovery | 8 | profiles the host before destroying data on it |
| execution + command-and-control | 6 | runs code fetched from somewhere else |
| obfuscation + execution | 6 | hides the command it is about to run |

### 3. Clamp and band

The total is clamped to `0–100` and mapped to a verdict:

| Score | Verdict |
|---|---|
| 0 – 9 | **benign** |
| 10 – 29 | **suspicious** |
| 30 – 59 | **likely-malicious** |
| 60 – 100 | **malicious** |

Bands are checked high-to-low with `>=`, so the boundaries (10, 30, 60) belong to the
higher verdict. The tests in `tests/test_scoring.py` pin every boundary.

## What does *not* affect the score

Only **core** rules feed the score. The PRO **extended** rules are appended to the report
*after* the score is computed (`analyze.py`), so by construction they can add detail but
can never move a free-tier verdict. `tests/test_analyze.py::test_pro_extended_rules_are_additive`
proves it by running the same file with and without a licence and asserting the score is
identical.

## Calibration on the synthetic corpus

Run `python fixtures/build.py` then triage each file. Representative results:

| Sample | Verdict | Score |
|---|---|---:|
| `benign_readme.txt` | benign | 6 |
| `xor_config.bin` | benign | 6 |
| `remote_template.docx` | benign | 9 |
| `js_dropper.js` | suspicious | 22 |
| `gzip_b64_payload.txt` | likely-malicious | 44 |
| `fake_injector.exe` | likely-malicious | 53 |
| `powershell_dropper.ps1` | malicious | 61 |

The benign control lands at benign; the layered droppers and the injector land where a
human would put them. These numbers are produced by the generator you can read, not
asserted.
