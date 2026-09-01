#!/usr/bin/env python3
"""Issue a signed revtriage PRO licence token — OFFLINE, from the private seed.

The signing seed lives only in ``.secrets/revtriage_license_ed25519.seed`` (git-ignored)
and never ships. This script is the single place that touches it. Verification, by
contrast, needs only the embedded public key, so anyone can check a token but only the
holder of the seed can mint one.

    python scripts/mint_license.py --subject "Acme SOC" --days 365 --features "*"

The token it prints goes to the customer, who sets it via ``REVTRIAGE_LICENSE`` or drops
it in ``~/.config/revtriage/license``.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Run from a checkout without installing.
_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))

from revtriage.license import verify_token  # noqa: E402
from revtriage.license.verify import TOKEN_PREFIX, SUPPORTED_VERSION, build_token  # noqa: E402

DEFAULT_SEED_PATH = Path(__file__).resolve().parent.parent / ".secrets" / "revtriage_license_ed25519.seed"


def _load_seed(path: Path) -> bytes:
    if not path.exists():
        raise SystemExit(
            f"signing seed not found at {path}.\n"
            "Generate one with:\n"
            "  python -c \"import os,sys; sys.path.insert(0,'src'); "
            "from revtriage.license import keys; "
            "s=os.urandom(32); open('.secrets/revtriage_license_ed25519.seed','w').write(s.hex()); "
            "print('public:', keys.public_from_seed(s).hex())\"\n"
            "then paste the public key into LICENSE_PUBLIC_KEY_HEX in src/revtriage/license/keys.py."
        )
    return bytes.fromhex(path.read_text(encoding="utf-8").strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Issue a signed revtriage PRO licence token.")
    parser.add_argument("--subject", required=True, help="who the licence is for")
    parser.add_argument(
        "--features", default="*",
        help="comma-separated feature list, or '*' for all PRO features (default: *)",
    )
    parser.add_argument("--days", type=int, default=365, help="validity in days; 0 = never expires")
    parser.add_argument("--seed", type=Path, default=DEFAULT_SEED_PATH, help="path to the signing seed")
    args = parser.parse_args(argv)

    seed = _load_seed(args.seed)
    now = datetime.now(timezone.utc)
    features = ["*"] if args.features.strip() == "*" else [f.strip() for f in args.features.split(",") if f.strip()]

    payload = {
        "format": TOKEN_PREFIX,
        "version": SUPPORTED_VERSION,
        "subject": args.subject,
        "tier": "pro",
        "features": features,
        "issued": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires": None if args.days == 0 else (now + timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    token = build_token(payload, seed)

    result = verify_token(token)
    if not result.valid:
        raise SystemExit(f"internal error: freshly minted token does not verify ({result.reason})")

    print(token)
    print(f"\n# subject : {args.subject}", file=sys.stderr)
    print(f"# features: {', '.join(features)}", file=sys.stderr)
    print(f"# expires : {payload['expires'] or 'never'}", file=sys.stderr)
    print(f"# verified: {result.reason}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
