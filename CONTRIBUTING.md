# Contributing to revtriage

Thanks for looking. revtriage has two hard rules that shape every contribution.

## The two non-negotiables

1. **Zero third-party runtime dependencies.** Everything under `src/revtriage/` imports
   only the Python standard library. This is a *security property*, not a style choice:
   the tool is pointed at hostile files, and the value proposition is that there is
   nothing third-party to audit. A PR that adds a runtime dependency will not be merged —
   find a stdlib way, or make it a `dev` extra used only by tests.
2. **The tool never executes the sample.** No `eval`, no `exec`, no `subprocess`, no
   dynamic import of sample content, no network calls. Analysis is parsing and pattern
   matching over `bytes`. If you think a feature needs to run the sample, it belongs in
   the (separate, gated) sandbox design — see `docs/sandbox-design.md`.

## Setup

```console
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e ".[dev]"
$ pytest
```

## Adding a capability rule

Rules live in `src/revtriage/capabilities/rules.py`.

- Every rule's `capability` must exist in `attack.CAPABILITIES`, and **every technique it
  references must exist in `attack.TECHNIQUES`.** Do not invent an ATT&CK id — if the
  technique you need isn't in the curated subset, add it to `attack.py` from the real
  catalogue at <https://attack.mitre.org/>, with its real name and tactic.
- `validate_rules` and `tests/test_capabilities.py` enforce both. Run `pytest -k
  capabilities` after any rule change.
- Extended (PRO) rules go in `EXTENDED_RULES` and must stay **additive** — they are
  reported separately and never feed the score.

## Tests must survive mutation

A test that passes whether or not the bug is present is worse than no test. When you
change scoring or deobfuscation, add a test and **mutate the code to prove the test
catches it**: flip the operator or threshold, run the test, confirm it goes red, restore.
The existing mutation-killers in `tests/test_scoring.py` and `tests/test_deobfuscate.py`
are the model. `assert x > 0` is not a test.

## Fixtures are generated, never committed

Samples are synthesised by `fixtures/build.py`. Keep them **inert** — strings and
structure, no working payload — and point every indicator at an RFC-2606 sinkhole
(`malware.example`, `example.com`, `127.0.0.1`). We do not commit binaries.

## Style

- Code and identifiers in English; comments explain the *why*, not the *what*.
- `from __future__ import annotations` at the top of every module.
- Keep parsers bounded: clamp every attacker-controlled count, size and offset before it
  becomes a loop bound or an allocation.

## The signing key

`scripts/mint_license.py` uses a private seed in `.secrets/` (git-ignored). It is never
committed and never needed to *use* or *test* revtriage — only to issue PRO tokens. Do not
add it, or any secret, to the repo.
