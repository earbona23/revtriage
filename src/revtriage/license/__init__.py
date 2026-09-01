"""Offline licensing: an Ed25519-signed token, verified with zero third-party code.

The public API the rest of revtriage uses is small: `load_license` to resolve and verify
whatever licence the environment provides, `gate` to turn a licence into an honest
`GatedFeature` for one PRO feature, and `verify_token` for direct verification.
"""

from __future__ import annotations

from .store import gate, load_license
from .verify import LicenseResult, build_token, verify_token

__all__ = ["load_license", "gate", "verify_token", "build_token", "LicenseResult"]
