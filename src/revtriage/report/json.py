"""The JSON report: the machine-readable contract.

It is exactly `Triage.to_dict()` with a small envelope. The shape is a promise other
tools depend on, which is why serialisation lives on the model (each field decides how it
is published) and this reporter only wraps it — there is nowhere here to accidentally
drop or rename a field.
"""

from __future__ import annotations

import json

from ..model import Triage


def to_json(triage: Triage, indent: int | None = 2) -> str:
    return json.dumps(triage.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)
