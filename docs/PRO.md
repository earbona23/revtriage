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

## Buying a licence
Licences are sold through a merchant of record (a Polar storefront is on the way). To
buy one now, or to ask about volume, email earbona@arrankago.com.
