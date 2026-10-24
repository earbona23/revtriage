# revtriage Pro

The triage engine is MIT and free forever. Pro adds the extended ATT&CK rule set and
the HTML report, unlocked by an offline, Ed25519-signed licence key that is verified
locally and never phones home.

## What Pro adds
- Extended detection rules beyond the free catalogue.
- A self-contained HTML report alongside the Markdown, JSON and STIX outputs.

## How to activate
Set the key in the environment, or write it to the config file:

    export REVTRIAGE_LICENSE="<token>"        # or ~/.config/revtriage/license

Free-tier verdicts never change when a key is present — Pro adds detail, it does not
move the score.

## Pricing

Per organisation, per month, in USD, with unlimited users inside the seat band. Annual billing
is two months free, so the yearly figure is ten times the monthly one. The licence is a signed
file, verified offline — no account, no phone-home.

| | Solo (1) | Team (≤10) | Business (≤50) | Enterprise |
|---|:--:|:--:|:--:|:--:|
| **Monthly** | **$39** | **$129** | **$399** | contact |
| **Annual** | $390 | $1,290 | $3,990 | contact |

These are the figures charged at **[consulting.arrankago.com](https://consulting.arrankago.com)**,
which is where they are maintained: if this page ever disagrees with that site, the site is right
and this page is stale. The bundle covering more than one tool is priced there too.

containment-cut is listed as a third tool elsewhere, but its Pro features are not
implemented yet, so it is **not part of this bundle and not on sale** — see
[its Pro page](https://github.com/earbona23/containment-cut/blob/main/docs/pro.md).

To buy, email **earbona@arrankago.com** with the name to put on the licence. You get the
key by return email, usually the same day.
