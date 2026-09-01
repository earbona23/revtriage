# Orchestrated detonation — design only (PRO)

> **Status: design document. Not implemented, and deliberately not shipped in this
> repository.** revtriage is 100% offline and **never executes a sample**. The gate for
> this feature always reports `skipped`, with this file as its reason. That is on
> purpose: an empty result must never be mistakable for "ran and found nothing".

Static triage answers *what a file can do*. Some questions — the real C2 after a
domain-generation algorithm, the second stage fetched only at runtime, the files actually
touched — only a controlled run answers. This document describes how a PRO tier *could*
orchestrate that **without** turning revtriage itself into something that runs malware.

## Principles

1. **The core tool never detonates.** Detonation is a separate, opt-in service the
   analyst points revtriage's static output at. The library in this repo has no
   evaluator, no interpreter, no `subprocess`, and that property is enforced by having
   zero runtime dependencies to hide one in.
2. **Ephemeral, disposable, network-contained.** Each run is a fresh microVM or container
   destroyed afterwards, on an isolated network with a sinkholed egress (an internal
   DNS/HTTP responder), so a live sample cannot reach real infrastructure or a second
   victim from the sandbox.
3. **Consent and provenance.** Detonation is destructive of the guarantee that "nothing
   ran", so it requires an explicit, logged opt-in per sample. The report records that a
   dynamic run happened, on what image, for how long.

## Sketch of the flow

```
static Triage (this tool)
      │  capabilities + IOCs give the sandbox its watch-list
      ▼
[ ephemeral sandbox ]  ── isolated net ──▶ [ sinkhole: DNS + HTTP responder ]
      │  syscalls, file writes, network attempts, spawned processes
      ▼
dynamic observations ── merged, as a NEW report section, with the static Triage
```

The dynamic layer only ever **adds** observed behaviour; it never rewrites a static
verdict, mirroring the additive rule the extended rules already follow.

## Why it is not in the box

Shipping a detonation harness in a pip-installable library would make "install revtriage"
mean "install something that can run malware on your host if misconfigured". The value of
a pure-static, zero-dependency triage tool is precisely that it cannot. So the capability
stays a documented design, gated and honest, until it can live as a separate, clearly
labelled service with its own isolation guarantees.
