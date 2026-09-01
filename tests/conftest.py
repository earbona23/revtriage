"""Shared fixtures: the synthetic corpus, built into a temp dir once per session.

We never commit binaries, so the tests build the corpus from `fixtures/build.py` — the
same generator a user runs — into a session-scoped temp directory. That also means the
tests exercise the exact bytes the README's quickstart produces.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _load_builder():
    spec = importlib.util.spec_from_file_location("_fixture_builder", ROOT / "fixtures" / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def corpus(tmp_path_factory) -> dict[str, bytes]:
    out = tmp_path_factory.mktemp("corpus")
    builder = _load_builder()
    builder.build(out)
    return {p.name: p.read_bytes() for p in out.iterdir()}


@pytest.fixture(scope="session")
def signing_seed() -> bytes:
    """The real signing seed if present (developer machine / CI secret), else a throwaway
    keypair generated for the test so licence tests never depend on the private key."""
    seed_path = ROOT / ".secrets" / "revtriage_license_ed25519.seed"
    if seed_path.exists():
        return bytes.fromhex(seed_path.read_text().strip())
    import os

    return os.urandom(32)
