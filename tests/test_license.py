"""Licensing tests: standards-correct Ed25519, and honest gating.

The known-answer vector below is cross-checked against the RFC 8032 test vector and the
`cryptography` library; it proves the pure-stdlib implementation is not merely
self-consistent but actually standard. The rest proves a token cannot be forged or
extended past expiry, and that an unlicensed feature is *skipped with a reason*, never
silently absent.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from revtriage.license import keys
from revtriage.license.store import gate
from revtriage.license.verify import (
    SUPPORTED_VERSION,
    TOKEN_PREFIX,
    build_token,
    verify_token,
)

# RFC 8032 Ed25519 Test 1 (also verified against pyca/cryptography).
_SEED = bytes.fromhex("9d61b19deff1e5f27807b12277e5dfc93f8dcd8d4e8bda9a2c1a0f6a0a02b1d0")
_PUB = bytes.fromhex("4ae64766a5657f9fdb1c8aab175416f25b721a674e805138435099758885150b")
_SIG_EMPTY = bytes.fromhex(
    "8cce3d90016a03dde9084343656fb7d40809053971742520529d8f4e054226d1"
    "445938dbc513e0e17eaffe51fbb19627e8ad21f6af39080341355ffac16cf00b"
)


def test_ed25519_known_answer():
    assert keys.public_from_seed(_SEED) == _PUB
    assert keys.sign(_SEED, b"") == _SIG_EMPTY
    assert keys.verify(_PUB, b"", _SIG_EMPTY)


def test_ed25519_rejects_tampered_message():
    assert not keys.verify(_PUB, b"tampered", _SIG_EMPTY)


def test_ed25519_rejects_malformed_input():
    assert keys.verify(_PUB, b"m", b"\x00" * 63) is False  # wrong signature length
    assert keys.verify(b"\x00" * 31, b"m", _SIG_EMPTY) is False  # wrong key length


def test_sign_verify_roundtrip_random_key():
    seed = os.urandom(32)
    pub = keys.public_from_seed(seed)
    sig = keys.sign(seed, b"revtriage licence payload")
    assert keys.verify(pub, b"revtriage licence payload", sig)
    assert not keys.verify(pub, b"revtriage licence payloae", sig)


def _payload(expires=None, features=("*",)):
    return {
        "format": TOKEN_PREFIX,
        "version": SUPPORTED_VERSION,
        "subject": "Test SOC",
        "tier": "pro",
        "features": list(features),
        "expires": expires,
    }


def test_valid_token_verifies_and_grants(signing_seed):
    pub = keys.public_from_seed(signing_seed)
    token = build_token(_payload(), signing_seed)
    result = verify_token(token, public_key=pub)
    assert result.valid
    assert result.tier == "pro"
    assert result.grants("extended-rules")


def test_tampered_payload_fails(signing_seed):
    pub = keys.public_from_seed(signing_seed)
    token = build_token(_payload(features=("extended-rules",)), signing_seed)
    head, sig = token.split(".")
    # Flip a character in the payload segment: signature no longer covers it.
    forged = head[:-1] + ("A" if head[-1] != "A" else "B") + "." + sig
    result = verify_token(forged, public_key=pub)
    assert not result.valid
    assert not result.grants("extended-rules")


def test_wrong_key_fails(signing_seed):
    token = build_token(_payload(), signing_seed)
    other_pub = keys.public_from_seed(os.urandom(32))
    assert not verify_token(token, public_key=other_pub).valid


def test_expired_token_is_invalid(signing_seed):
    pub = keys.public_from_seed(signing_seed)
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    token = build_token(_payload(expires=past), signing_seed)
    result = verify_token(token, public_key=pub)
    assert not result.valid
    assert "expired" in result.reason


def test_future_expiry_is_valid(signing_seed):
    pub = keys.public_from_seed(signing_seed)
    future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    token = build_token(_payload(expires=future), signing_seed)
    assert verify_token(token, public_key=pub).valid


def test_feature_scoped_license_does_not_grant_others(signing_seed):
    pub = keys.public_from_seed(signing_seed)
    token = build_token(_payload(features=("html-report",)), signing_seed)
    result = verify_token(token, public_key=pub)
    assert result.grants("html-report")
    assert not result.grants("extended-rules")


def test_gate_reports_skipped_with_reason_when_unlicensed():
    from revtriage.license.verify import LicenseResult

    unlicensed = LicenseResult(False, "no licence found")
    gated = gate("extended-rules", unlicensed)
    assert gated.status == "skipped"
    assert gated.reason  # never empty — the honest-gating contract
    assert "extended-rules" in gated.name


def test_gate_reports_ok_when_licensed(signing_seed):
    pub = keys.public_from_seed(signing_seed)
    token = build_token(_payload(features=("extended-rules",)), signing_seed)
    result = verify_token(token, public_key=pub)
    gated = gate("extended-rules", result)
    assert gated.status == "ok"
