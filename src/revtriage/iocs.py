"""Indicator-of-compromise extraction.

IOCs are pulled from *every* layer, not just the original file, and each indicator
remembers the layer it surfaced in. That provenance is the whole value: "this C2 URL
appeared only after the PowerShell -EncodedCommand was decoded" is an actionable fact,
where "this file contains a URL somewhere" is not.

The extractor is tuned for precision over recall on the noisy types. A tool that reports
forty domains, thirty-eight of which are `kernel32.dll` and `schema.org`, trains the
analyst to ignore the section — so standalone hostnames are only accepted against a
curated TLD list and are rejected when they look like a filename. URLs and their hosts,
being unambiguous, are taken as-is. Values are stored raw; `defang` is offered for
display so a report can be pasted somewhere without becoming clickable.
"""

from __future__ import annotations

import re

from .model import Indicator

_URL = re.compile(r"\b(?:https?|ftp|ftps)://[^\s'\"<>\)\]\}\\]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?![\d.])")
_REGISTRY = re.compile(
    r"HK(?:EY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|LM|CU|CR|U|CC)"
    r":?[\\/][^\s'\"<>|,;]{2,240}",  # accept the PowerShell drive form HKCU:\... too
)
# The negative lookbehind stops the drive letter of a registry path (the 'U' in 'HKCU:\')
# being re-extracted as a bare filesystem path.
_WIN_PATH = re.compile(r"(?<![A-Za-z])[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]{1,}")
_UNC_PATH = re.compile(r"\\\\[A-Za-z0-9_.\-]+\\[^\s'\"<>|]{1,240}")
_UNIX_PATH = re.compile(r"(?<![\w.])/(?:etc|tmp|var|usr|bin|sbin|home|root|opt|dev|proc)/[^\s'\"<>|,;]{1,240}")
_HOST = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})\b")

#: Standalone hostnames are only trusted when the final label is one of these. It keeps
#: `schtasks.exe` and `kernel32.dll` out of the domain list while still catching the
#: hostnames an implant actually talks to. Hosts inside a URL bypass this — they are
#: already unambiguous.
COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "ru", "cn", "xyz", "top", "site",
    "online", "club", "shop", "app", "dev", "cloud", "me", "tv", "cc", "ws", "su", "to",
    "pw", "gov", "edu", "int", "mil", "uk", "de", "fr", "nl", "br", "in", "ir", "ua",
    "pl", "es", "it", "eu", "ca", "au", "jp", "kr", "tk", "ml", "ga", "cf", "gq", "onion",
    "live", "life", "world", "store", "tech", "space", "fun", "icu", "pro", "vip", "cyou",
}

#: Final labels that look like a hostname but are a filename. Rejected outright.
_FILE_LIKE_TLDS = {
    "dll", "exe", "sys", "bin", "dat", "tmp", "log", "ini", "cfg", "bat", "cmd", "ps1",
    "vbs", "js", "py", "sh", "php", "asp", "aspx", "html", "htm", "xml", "json", "txt",
    "png", "jpg", "gif", "ico", "css", "class", "jar", "so", "dylib", "o", "obj", "lib",
}

MAX_PER_TYPE = 500


def extract(texts: list[tuple[str, str]]) -> list[Indicator]:
    """Extract indicators from `(layer_id, text)` pairs, deduplicated across all layers."""
    indicators: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    counts: dict[str, int] = {}

    def add(kind: str, value: str, layer: str, context: str = "") -> None:
        value = value.strip().rstrip(".,;)")
        if not value:
            return
        key = (kind, value.lower())
        if key in seen:
            return
        if counts.get(kind, 0) >= MAX_PER_TYPE:
            return
        seen.add(key)
        counts[kind] = counts.get(kind, 0) + 1
        indicators.append(Indicator(type=kind, value=value, layer=layer, context=context))

    for layer_id, text in texts:
        for match in _URL.finditer(text):
            url = match.group()
            add("url", url, layer_id)
            host = _url_host(url)
            if host:
                if _is_ipv4(host):
                    add("ipv4", host, layer_id, context="host of a URL")
                else:
                    add("domain", host, layer_id, context="host of a URL")

        for match in _EMAIL.finditer(text):
            add("email", match.group(), layer_id)

        for match in _IPV4.finditer(text):
            octets = match.group(1)
            if _is_ipv4(octets):
                add("ipv4", octets, layer_id)

        for match in _REGISTRY.finditer(text):
            add("registry_key", match.group(), layer_id)

        for match in _UNC_PATH.finditer(text):
            add("windows_path", match.group(), layer_id, context="UNC path")
        for match in _WIN_PATH.finditer(text):
            add("windows_path", match.group(), layer_id)
        for match in _UNIX_PATH.finditer(text):
            add("unix_path", match.group(), layer_id)

        for match in _HOST.finditer(text):
            host = match.group(0)
            tld = match.group(1).lower()
            if _plausible_standalone_host(host, tld):
                add("domain", host, layer_id, context="standalone hostname")

    return indicators


def _url_host(url: str) -> str | None:
    after_scheme = url.split("://", 1)[-1]
    authority = re.split(r"[/?#]", after_scheme, maxsplit=1)[0]
    authority = authority.split("@")[-1]  # drop userinfo
    host = authority.split(":", 1)[0]  # drop port
    return host or None


def _is_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts) and value != "0.0.0.0"
    except ValueError:
        return False


def _plausible_standalone_host(host: str, tld: str) -> bool:
    if tld in _FILE_LIKE_TLDS or tld not in COMMON_TLDS:
        return False
    if _is_ipv4(host):
        return False
    labels = host.split(".")
    # A bare two-letter-or-fewer left label like "a.io" is more often noise than a host.
    if len(labels) < 2 or len(labels[0]) < 2:
        return False
    return True


_DEFANG = str.maketrans({".": "[.]"})


def defang(value: str) -> str:
    """Make an indicator safe to paste: `http` → `hxxp`, `.` → `[.]`. Display only."""
    return value.replace("http", "hxxp").replace("ftp", "fxp").translate(_DEFANG)
