"""The deobfuscation loop: breadth-first, budgeted, and provenance-preserving.

Layer 0 is the file. Every technique is offered every layer; anything that decodes to
something `score.is_interesting` accepts becomes a new layer whose `parent` points at
where it came from. The walk is breadth-first so that the cheap, shallow layers — where
most indicators live — are always produced before the budget is spent on a deep chain.

Three budgets bound the work, and all three exist because the input is adversarial:

* ``max_depth``  — an obfuscator can nest forever; an analyst cannot read forever.
* ``max_layers`` — caps the total report size.
* ``max_bytes``  — caps memory against decompression bombs.

When a budget stops the walk the fact is recorded and surfaced, because "we stopped
looking" and "there was nothing more to find" must never look the same in a report.
"""

from __future__ import annotations

import hashlib

from ..model import Layer
from . import compression, encoding, powershell, xor
from .score import interest, is_interesting

DEFAULT_MAX_DEPTH = 4
DEFAULT_MAX_LAYERS = 24
DEFAULT_MAX_BYTES = 16 * 1024 * 1024


def deobfuscate(
    data: bytes,
    extra_bodies: list[tuple[str, bytes]] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_layers: int = DEFAULT_MAX_LAYERS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> tuple[list[Layer], list[str]]:
    """Return (layers, notes). `layers[0]` is always the original file."""
    notes: list[str] = []
    root = Layer(id="L0", depth=0, technique="original", description="the file as supplied", data=data)
    layers: list[Layer] = [root]
    seen: set[str] = {_digest(data)}
    budget = max_bytes - len(data)

    queue: list[Layer] = [root]

    # Embedded bodies (macro source, a script inside an archive) enter as depth-1 layers:
    # they were extracted structurally rather than decoded, but everything downstream —
    # rules, IOCs, further deobfuscation — must treat them like any other layer.
    for name, body in extra_bodies or []:
        if not body:
            continue
        digest = _digest(body)
        if digest in seen or len(layers) >= max_layers:
            continue
        seen.add(digest)
        layer = Layer(
            id=f"L{len(layers)}",
            depth=1,
            technique="embedded",
            description=f"embedded content: {name}",
            data=body[:max_bytes],
            parent=root.id,
        )
        layers.append(layer)
        queue.append(layer)
        budget -= len(layer.data)

    while queue:
        current = queue.pop(0)
        if current.depth >= max_depth:
            if current.depth == max_depth:
                notes.append("deobfuscate:depth-limit-reached")
            continue
        for technique, description, decoded in _candidates(current.data):
            if len(layers) >= max_layers:
                notes.append("deobfuscate:layer-limit-reached")
                queue.clear()
                break
            if budget <= 0:
                notes.append("deobfuscate:size-limit-reached")
                queue.clear()
                break
            if len(decoded) < 8:
                continue
            digest = _digest(decoded)
            if digest in seen:
                continue
            if not is_interesting(decoded):
                continue
            seen.add(digest)
            trimmed = decoded[: min(len(decoded), budget)]
            budget -= len(trimmed)
            layer = Layer(
                id=f"L{len(layers)}",
                depth=current.depth + 1,
                technique=technique,
                description=f"{description} (interest {interest(decoded)})",
                data=trimmed,
                parent=current.id,
            )
            layers.append(layer)
            queue.append(layer)

    return layers, sorted(set(notes))


def _candidates(data: bytes) -> list[tuple[str, str, bytes]]:
    """Every technique's output for one layer, cheapest first."""
    out: list[tuple[str, str, bytes]] = []
    out.extend(compression.unwrap(data))
    out.extend(powershell.unwrap(data))
    out.extend(encoding.decode_all(data))
    out.extend(xor.recover(data))
    return out


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
