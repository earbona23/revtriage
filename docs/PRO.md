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

Per organisation, unlimited seats. The licence is a signed file, verified offline — no
account, no phone-home.

| | Monthly | Annual (two months free) |
|---|:--:|:--:|
| This tool, Pro | US$29 | US$290 |
| All three tools (revtriage · EntraTripwire · containment-cut) | US$69 | US$690 |

To buy, email **earbona@arrankago.com** with the name to put on the licence. You get the
key by return email, usually the same day.
