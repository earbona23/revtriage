"""Layered deobfuscation.

Obfuscation in the wild is stacked, not singular: a macro concatenates a string, that
string is base64, the decoded bytes are XORed with one byte, and the result is gzip. Each
technique here peels exactly one layer and hands its output back to the pipeline, which
re-runs every technique on the result until nothing new appears or a budget is reached.

The pipeline never executes anything. Every step is a decode, a decompress or a
pattern-driven fold — the tool has no evaluator, no interpreter and no subprocess, by
design, because the input is malware.
"""

from __future__ import annotations

from .pipeline import deobfuscate

__all__ = ["deobfuscate"]
