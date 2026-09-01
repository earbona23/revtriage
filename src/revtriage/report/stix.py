"""STIX 2.1 bundle output, and a structural validator for it.

Why emit STIX at all: a triage verdict that stays in a Markdown file dies there. STIX is
how the finding travels — into a TIP, a SIEM watchlist, a sharing group — without a human
re-keying every indicator. This writer produces a self-contained 2.1 bundle:

* one **identity** SDO — revtriage, the creator of everything else in the bundle;
* one **file** SCO — the analysed sample, keyed on its hashes;
* one **indicator** SDO per mappable IOC, each with a real STIX pattern;
* one **attack-pattern** SDO per ATT&CK technique, with the external reference an analyst
  needs to look it up;
* one **report** SDO tying them together.

Object identifiers are derived from content with `uuid5`, so re-running the triage on the
same file yields byte-identical objects — a diff between two reports shows real change,
not fresh random UUIDs. `validate_bundle` checks the structure the spec requires (id
format, required properties, dangling references, uniqueness) and is exercised by a test,
because an "invalid but plausible" bundle is worse than none: it fails on import, in
someone else's pipeline, after the analyst has moved on.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from ..model import Triage
from .. import __version__

# Namespaces. The first is the STIX 2.1 namespace used for deterministic SCO ids; the
# second is a project-local namespace for deterministic SDO ids.
_STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
_REVTRIAGE_NS = uuid.UUID("6a9f6d1e-6f6a-5c2e-9a4a-2f1b6d3c8e57")

_STIX_TIMESTAMP = "%Y-%m-%dT%H:%M:%S.000Z"

#: IOC type → (STIX SCO type, property that holds the value in a pattern).
_PATTERN_MAP = {
    "url": ("url", "value"),
    "domain": ("domain-name", "value"),
    "ipv4": ("ipv4-addr", "value"),
    "email": ("email-addr", "value"),
    "registry_key": ("windows-registry-key", "key"),
}


def _now(now: datetime | None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime(_STIX_TIMESTAMP)


def _det_id(prefix: str, *parts: str, sco: bool = False) -> str:
    namespace = _STIX_NS if sco else _REVTRIAGE_NS
    return f"{prefix}--{uuid.uuid5(namespace, '|'.join(parts))}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def to_stix_bundle(triage: Triage, now: datetime | None = None) -> dict:
    timestamp = _now(now)
    objects: list[dict] = []

    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _det_id("identity", "revtriage"),
        "created": timestamp,
        "modified": timestamp,
        "name": "revtriage",
        "identity_class": "system",
        "description": f"revtriage {__version__} — offline reverse-engineering triage.",
    }
    creator = identity["id"]
    objects.append(identity)

    file_sco = _file_sco(triage, creator)
    objects.append(file_sco)

    object_refs: list[str] = [file_sco["id"]]

    for indicator in _indicators(triage, timestamp, creator):
        objects.append(indicator)
        object_refs.append(indicator["id"])

    for pattern in _attack_patterns(triage, timestamp, creator):
        objects.append(pattern)
        object_refs.append(pattern["id"])

    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": _det_id("report", "report", triage.hashes.get("sha256", triage.filename)),
        "created_by_ref": creator,
        "created": timestamp,
        "modified": timestamp,
        "name": f"revtriage triage of {triage.filename}",
        "report_types": ["malware"],
        "published": timestamp,
        "object_refs": object_refs,
        "description": (
            f"Verdict: {triage.score.verdict if triage.score else 'n/a'} "
            f"(score {triage.score.value if triage.score else 0}/100)."
        ),
    }
    objects.append(report)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_REVTRIAGE_NS, 'bundle|' + triage.hashes.get('sha256', triage.filename))}",
        "objects": objects,
    }


def _file_sco(triage: Triage, creator: str) -> dict:
    hashes = {}
    if triage.hashes.get("md5"):
        hashes["MD5"] = triage.hashes["md5"]
    if triage.hashes.get("sha1"):
        hashes["SHA-1"] = triage.hashes["sha1"]
    if triage.hashes.get("sha256"):
        hashes["SHA-256"] = triage.hashes["sha256"]
    sco = {
        "type": "file",
        "spec_version": "2.1",
        "id": _det_id("file", triage.hashes.get("sha256", triage.filename), sco=True),
        "hashes": hashes,
        "size": triage.size,
        "name": triage.filename,
    }
    return sco


def _indicators(triage: Triage, timestamp: str, creator: str) -> list[dict]:
    out: list[dict] = []
    for indicator in triage.indicators:
        mapping = _PATTERN_MAP.get(indicator.type)
        if mapping is None:
            continue
        sco_type, prop = mapping
        pattern = f"[{sco_type}:{prop} = '{_escape(indicator.value)}']"
        out.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _det_id("indicator", indicator.type, indicator.value),
                "created_by_ref": creator,
                "created": timestamp,
                "modified": timestamp,
                "name": f"{indicator.type}: {indicator.value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": timestamp,
                "labels": ["malicious-activity"],
                "description": f"Observed in layer {indicator.layer}."
                + (f" {indicator.context}." if indicator.context else ""),
            }
        )
    return out


def _attack_patterns(triage: Triage, timestamp: str, creator: str) -> list[dict]:
    from ..capabilities import attack

    out: list[dict] = []
    for technique_id in triage.techniques:
        technique = attack.TECHNIQUES.get(technique_id)
        if technique is None:
            continue
        out.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": _det_id("attack-pattern", technique_id),
                "created_by_ref": creator,
                "created": timestamp,
                "modified": timestamp,
                "name": technique.name,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                        "url": technique.url,
                    }
                ],
            }
        )
    return out


# -- validation ----------------------------------------------------------------------

_ID_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")


def validate_bundle(bundle: dict) -> list[str]:
    """Return a list of STIX-2.1 structural problems; an empty list means the bundle is
    well-formed. This is not a full spec validator — it is the set of invariants whose
    violation makes a bundle fail to import elsewhere."""
    problems: list[str] = []

    if bundle.get("type") != "bundle":
        problems.append("bundle: type is not 'bundle'")
    if not _ID_RE.match(bundle.get("id", "")) or not bundle.get("id", "").startswith("bundle--"):
        problems.append(f"bundle: malformed id {bundle.get('id')!r}")

    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        problems.append("bundle: 'objects' must be a non-empty list")
        return problems

    ids: set[str] = set()
    for index, obj in enumerate(objects):
        where = f"objects[{index}] ({obj.get('type', '?')})"
        obj_id = obj.get("id", "")
        obj_type = obj.get("type", "")
        if not obj_type:
            problems.append(f"{where}: missing type")
        if not _ID_RE.match(obj_id):
            problems.append(f"{where}: malformed id {obj_id!r}")
        elif not obj_id.startswith(f"{obj_type}--"):
            problems.append(f"{where}: id prefix does not match type")
        if obj_id in ids:
            problems.append(f"{where}: duplicate id {obj_id}")
        ids.add(obj_id)

        # SDOs (everything that is not a pure SCO here) carry spec_version + timestamps.
        if obj_type in ("identity", "indicator", "attack-pattern", "report"):
            if obj.get("spec_version") != "2.1":
                problems.append(f"{where}: spec_version is not '2.1'")
            for field in ("created", "modified"):
                if not _TS_RE.match(obj.get(field, "")):
                    problems.append(f"{where}: {field} is not a STIX timestamp")

        if obj_type == "indicator":
            if not obj.get("pattern"):
                problems.append(f"{where}: indicator has no pattern")
            if obj.get("pattern_type") != "stix":
                problems.append(f"{where}: indicator pattern_type is not 'stix'")
            if not _TS_RE.match(obj.get("valid_from", "")):
                problems.append(f"{where}: indicator valid_from is not a STIX timestamp")

        if obj_type == "attack-pattern":
            refs = obj.get("external_references", [])
            if not any(r.get("source_name") == "mitre-attack" and r.get("external_id") for r in refs):
                problems.append(f"{where}: attack-pattern lacks a mitre-attack external reference")

        if obj_type == "file":
            if obj.get("spec_version") != "2.1":
                problems.append(f"{where}: file SCO spec_version is not '2.1'")
            if not obj.get("hashes"):
                problems.append(f"{where}: file SCO has no hashes")

    # Report references must all resolve inside the bundle.
    for obj in objects:
        if obj.get("type") == "report":
            refs = obj.get("object_refs", [])
            if not refs:
                problems.append("report: object_refs is empty")
            for ref in refs:
                if ref not in ids:
                    problems.append(f"report: dangling object_ref {ref}")

    return problems
