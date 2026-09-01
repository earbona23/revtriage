"""PowerShell-specific unwrapping: -EncodedCommand and the usual string mangling.

`powershell -enc <base64>` is its own layer rather than a generic base64 run because the
payload is UTF-16LE and because the switch can be abbreviated to anything from `-e`
upwards — PowerShell resolves parameters by unique prefix, which attackers use to defeat
naive string matching. Matching the prefix form is the point.
"""

from __future__ import annotations

import base64
import binascii
import re

_ENCODED_COMMAND = re.compile(
    rb"-\s*(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|"
    rb"encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+"
    rb"['\"]?(?P<payload>[A-Za-z0-9+/=]{20,})['\"]?",
    re.IGNORECASE,
)
_FROM_BASE64 = re.compile(
    rb"FromBase64String\s*\(\s*['\"](?P<payload>[A-Za-z0-9+/=]{16,})['\"]", re.IGNORECASE
)
#: `'ab' + 'cd'` and `"ab" + "cd"`, the laziest possible string-splitting obfuscation.
_CONCAT_PAIR = re.compile(rb"(['\"])([^'\"\r\n]{0,120})\1\s*\+\s*(['\"])([^'\"\r\n]{0,120})\3")
#: `-join`ed character arrays and the `'{1}{0}' -f` format trick are left to the rules,
#: which match on the construct itself; folding them would need an evaluator.
_TICK_ESCAPE = re.compile(rb"`(?=[A-Za-z])")


def unwrap(data: bytes) -> list[tuple[str, str, bytes]]:
    out: list[tuple[str, str, bytes]] = []

    for match in _ENCODED_COMMAND.finditer(data):
        payload = match.group("payload")
        decoded = _b64(payload)
        if decoded is None:
            continue
        try:
            text = decoded.decode("utf-16-le").encode("utf-8")
            out.append(("powershell-enc", "-EncodedCommand payload (UTF-16LE)", text))
        except (UnicodeDecodeError, UnicodeEncodeError):
            out.append(("powershell-enc", "-EncodedCommand payload (raw bytes)", decoded))

    for match in _FROM_BASE64.finditer(data):
        decoded = _b64(match.group("payload"))
        if decoded is not None:
            out.append(("frombase64string", "FromBase64String literal", decoded))

    folded = fold_concatenation(data)
    if folded is not None:
        out.append(("string-concat", "adjacent quoted strings folded together", folded))

    # A backtick before a letter is a no-op escape whose only purpose is to break
    # signatures: `p`o`w`e`r`s`h`e`l`l is still powershell.
    if _TICK_ESCAPE.search(data):
        stripped = _TICK_ESCAPE.sub(b"", data)
        if stripped != data:
            out.append(("backtick-escape", "backtick escapes removed", stripped))

    return out


def fold_concatenation(data: bytes, rounds: int = 8) -> bytes | None:
    """Repeatedly join `'a' + 'b'` into `'ab'`. Returns None when nothing folded.

    Bounded rounds rather than "until stable": the substitution is monotone but the input
    is attacker-controlled, and a fixed budget cannot be turned into a hang.
    """
    current = data
    changed = False
    for _ in range(rounds):
        folded = _CONCAT_PAIR.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), current)
        if folded == current:
            break
        current = folded
        changed = True
    return current if changed else None


def _b64(payload: bytes) -> bytes | None:
    padded = payload + b"=" * (-len(payload) % 4)
    try:
        decoded = base64.b64decode(padded)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) >= 8 else None
