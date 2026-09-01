"""Where a licence comes from, and the gate that decides free vs PRO.

Resolution order, first hit wins:

1. an explicit token passed on the command line (`--license <token>`);
2. the ``REVTRIAGE_LICENSE`` environment variable (the token itself);
3. the ``REVTRIAGE_LICENSE_FILE`` environment variable (a path to a token file);
4. the per-user file ``~/.config/revtriage/license`` (XDG-respecting).

The important design rule lives in `gate`: a PRO feature that is not licensed must return
a ``GatedFeature`` with ``status='skipped'`` and a human reason — never an empty result
that reads as "ran and found nothing". That distinction is the whole point of the
`GatedFeature` type, and it is the difference between honest gating and a silent
degradation the user cannot see.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..model import GatedFeature
from .verify import LicenseResult, verify_token

ENV_TOKEN = "REVTRIAGE_LICENSE"
ENV_FILE = "REVTRIAGE_LICENSE_FILE"


def default_license_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "revtriage" / "license"


def _read_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None


def find_token(explicit: str | None = None) -> str | None:
    """Return the first token found by the resolution order, or None."""
    if explicit:
        return explicit.strip()

    env_token = os.environ.get(ENV_TOKEN)
    if env_token and env_token.strip():
        return env_token.strip()

    env_file = os.environ.get(ENV_FILE)
    if env_file:
        contents = _read_file(Path(env_file))
        if contents:
            return contents

    default = default_license_path()
    if default.exists():
        contents = _read_file(default)
        if contents:
            return contents

    return None


def load_license(explicit: str | None = None) -> LicenseResult:
    """Resolve and verify a licence. Always returns a `LicenseResult` — an absent licence
    is a valid, expected state (free tier), not an error."""
    token = find_token(explicit)
    if token is None:
        return LicenseResult(False, "no licence found — running in free tier")
    return verify_token(token)


def gate(feature: str, license_result: LicenseResult) -> GatedFeature:
    """Decide whether a PRO feature may run, and return the honest record either way."""
    if license_result.grants(feature):
        return GatedFeature(name=feature, status="ok", reason="licensed")
    if license_result.valid:
        reason = f"the licence is valid but does not include the '{feature}' feature"
    else:
        reason = f"PRO feature — requires a licence ({license_result.reason})"
    return GatedFeature(name=feature, status="skipped", reason=reason)
