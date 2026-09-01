"""Reporters. One `Triage`, three renderings, no analysis logic here.

Everything a reporter shows was decided upstream in `analyze`; a reporter only chooses a
shape. That separation is deliberate — a bug in the Markdown layout can never change the
verdict, and the JSON contract can be regenerated from the same object the humans read.
"""

from __future__ import annotations

from .json import to_json
from .markdown import to_markdown
from .stix import to_stix_bundle, validate_bundle

__all__ = ["to_json", "to_markdown", "to_stix_bundle", "validate_bundle"]
