"""Licence token format and verification.

A revtriage PRO licence is a short, offline, self-contained token — no server to call,
no phone-home, which is the same property the whole tool is built around. The format is
deliberately JWT-shaped but stripped of JWT's footguns: there is exactly one algorithm
(Ed25519), it is not negotiable, and there is no `alg` field an attacker could set to
`none`. A token is two base64url segments joined by a dot:

    base64url(canonical_json_payload) . base64url(ed25519_signature)

The signature covers the canonical JSON bytes. `verify_token` returns a `LicenseResult`
that always states *why* a token is or is not valid, because the caller (the gate around
a PRO feature) has to be able to tell the user "expired 3 days ago" rather than a bare
"invalid".
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import keys

TOKEN_PREFIX = "revtriage-pro"
SUPPORTED_VERSION = 1


@dataclass(frozen=True)
class LicenseResult:
    valid: bool
    reason: str
    subject: str = ""
    tier: str = "free"
    features: tuple[str, ...] = ()
    expires: str | None = None
    payload: dict = field(default_factory=dict)

    def grants(self, feature: str) -> bool:
        """A valid licence grants a feature if it is listed, or if it carries the
        wildcard '*'. An invalid licence grants nothing, ever."""
        if not self.valid:
            return False
        return "*" in self.features or feature in self.features


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonical_payload(payload: dict) -> bytes:
    """The exact bytes that get signed: JSON with sorted keys and no incidental
    whitespace, so that re-serialising the same payload always yields the same signature
    input on every platform."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_token(payload: dict, seed: bytes) -> str:
    """Sign a payload and return a token. Used only by the offline minting script."""
    message = canonical_payload(payload)
    signature = keys.sign(seed, message)
    return f"{_b64url_encode(message)}.{_b64url_encode(signature)}"


def verify_token(token: str, public_key: bytes | None = None, now: datetime | None = None) -> LicenseResult:
    """Verify a licence token against the embedded public key (or an override, for tests)."""
    public = public_key if public_key is not None else keys.license_public_key()
    now = now or datetime.now(timezone.utc)

    token = (token or "").strip()
    if not token:
        return LicenseResult(False, "no licence token supplied")
    if token.count(".") != 1:
        return LicenseResult(False, "malformed token: expected two dot-separated segments")

    payload_segment, signature_segment = token.split(".", 1)
    try:
        message = _b64url_decode(payload_segment)
        signature = _b64url_decode(signature_segment)
    except (binascii.Error, ValueError):
        return LicenseResult(False, "malformed token: base64url decoding failed")

    # Signature is checked before the payload is trusted for anything at all.
    if not keys.verify(public, message, signature):
        return LicenseResult(False, "signature does not verify against the revtriage key")

    try:
        payload = json.loads(message)
    except json.JSONDecodeError:
        return LicenseResult(False, "signed payload is not valid JSON")
    if not isinstance(payload, dict):
        return LicenseResult(False, "signed payload is not an object")

    if payload.get("format") != TOKEN_PREFIX:
        return LicenseResult(False, f"not a {TOKEN_PREFIX} token")
    if payload.get("version") != SUPPORTED_VERSION:
        return LicenseResult(False, f"unsupported licence version {payload.get('version')!r}")

    subject = str(payload.get("subject", ""))
    tier = str(payload.get("tier", "pro"))
    features = tuple(str(f) for f in payload.get("features", []))
    expires = payload.get("expires")

    if expires is not None:
        expiry = _parse_time(str(expires))
        if expiry is None:
            return LicenseResult(False, "licence has an unparseable expiry date")
        if now > expiry:
            return LicenseResult(
                False,
                f"licence expired on {expiry.date().isoformat()}",
                subject=subject, tier=tier, features=features, expires=str(expires), payload=payload,
            )

    return LicenseResult(
        True,
        "valid licence",
        subject=subject, tier=tier, features=features,
        expires=str(expires) if expires is not None else None,
        payload=payload,
    )


def _parse_time(value: str) -> datetime | None:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        # Accept a bare date (YYYY-MM-DD) as end-of-day UTC.
        try:
            parsed = datetime.strptime(value.strip(), "%Y-%m-%d")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
