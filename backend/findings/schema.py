"""Dynamic / structured finding schema — open·kritt's ``schema.py``, ported dependency-free.

WHAT THIS IS
open·kritt lets a finding carry a **configurable field set** validated against a generated
jsonschema, so every producer emits the same machine-checkable shape. HackPit has producers
on every surface — recon, nuclei, AD, cloud, code-audit, the manual paste box — and each one
described a finding a little differently. This module gives them one shape: a base field set
(title, severity, target, attacker-path, source-refs, CVSS, vuln-class, evidence, reference)
plus an ``extra`` map for **engagement-defined custom fields** (the "dynamic" part).

It is PURE DATA. It validates and coerces dicts; it imports nothing from HackPit, executes
nothing, opens no socket. The bridge that turns a validated dict into a persisted
``state.models.Finding`` lives in the app layer (main.py), exactly like the codescan sink —
so this package stays orthogonal to the attack surface and hermetically testable.

Ported symbols (open·kritt names kept): ``FIELD_TYPE_MAP``, ``normalize_output_format``,
``output_schema``, ``validate_payload``, ``_kritt_extractor_helper``.
"""

from __future__ import annotations

import re
from typing import Any

# --------------------------------------------------------------------------- #
# severity vocabulary — canonical is the engagement-state vocab (5 levels).
# open·kritt uses "informational"; we accept it and normalize it to "info".
# --------------------------------------------------------------------------- #
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")
_SEVERITY_ALIASES = {
    "informational": "info", "information": "info", "note": "info", "": "info",
    "error": "high", "warning": "medium", "moderate": "medium", "severe": "critical",
}


def normalize_severity(value: Any) -> str:
    """Any producer's severity word -> one of :data:`SEVERITY_LEVELS`. Unknown -> 'info'."""
    s = str(value or "").strip().lower()
    s = _SEVERITY_ALIASES.get(s, s)
    return s if s in SEVERITY_LEVELS else "info"


# --------------------------------------------------------------------------- #
# field types — the FIELD_TYPE_MAP. Each entry is (python-check, coercer).
# The coercer NEVER raises: a wrong-typed value is coaxed toward the target
# type or dropped to that type's empty, so one bad field never sinks a finding.
# --------------------------------------------------------------------------- #
_CVSS_RE = re.compile(r"^CVSS:\d+\.\d+/[A-Z]{1,3}:[A-Z]", re.I)


def _coerce_string(v: Any) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)):
        return " ".join(str(x) for x in v)
    return "" if v is None else str(v)


def _coerce_list(v: Any) -> list[str]:
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, tuple):
        return [str(x).strip() for x in v if str(x).strip()]
    text = _coerce_string(v).strip()
    return [text] if text else []


def _coerce_severity(v: Any) -> str:
    return normalize_severity(v)


def _coerce_cvss(v: Any) -> str:
    text = _coerce_string(v).strip()
    return text if _CVSS_RE.match(text) else ""


def _coerce_number(v: Any) -> float | int:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0
    return int(f) if f.is_integer() else f


def _coerce_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _coerce_map(v: Any) -> dict[str, Any]:
    return dict(v) if isinstance(v, dict) else {}


# name -> (json-type label, python isinstance check, coercer)
FIELD_TYPE_MAP: dict[str, tuple[str, Any, Any]] = {
    "string": ("string", str, _coerce_string),
    "text": ("string", str, _coerce_string),
    "severity": ("string", str, _coerce_severity),
    "cvss": ("string", str, _coerce_cvss),
    "list": ("array", list, _coerce_list),
    "refs": ("array", list, _coerce_list),
    "number": ("number", (int, float), _coerce_number),
    "bool": ("boolean", bool, _coerce_bool),
    "map": ("object", dict, _coerce_map),
}


# --------------------------------------------------------------------------- #
# the base field set. A field spec is {name, type, required, label}.
# Producers may extend this per engagement; unknown keys land in ``extra``.
# --------------------------------------------------------------------------- #
DEFAULT_FIELDS: list[dict[str, Any]] = [
    {"name": "title", "type": "string", "required": True, "label": "Title"},
    {"name": "severity", "type": "severity", "required": True, "label": "Severity"},
    {"name": "target", "type": "string", "required": False, "label": "Target"},
    {"name": "vuln_class", "type": "string", "required": False, "label": "Class"},
    {"name": "attacker_path", "type": "text", "required": False, "label": "Attacker path"},
    {"name": "source_refs", "type": "refs", "required": False, "label": "Source refs"},
    {"name": "cvss", "type": "cvss", "required": False, "label": "CVSS"},
    {"name": "evidence", "type": "text", "required": False, "label": "Evidence"},
    {"name": "reference", "type": "string", "required": False, "label": "Reference"},
    {"name": "tool", "type": "string", "required": False, "label": "Tool"},
]

_BASE_NAMES = frozenset(f["name"] for f in DEFAULT_FIELDS)


def normalize_output_format(fields: Any) -> list[dict[str, Any]]:
    """Normalize an engagement's field spec into canonical {name, type, required, label} dicts.

    Accepts the shorthand open·kritt takes: a plain name (``"impact"``), a ``name:type`` string
    (``"impact:text"``), a trailing ``!`` for required (``"impact:text!"``), or a full dict. An
    unknown type falls back to ``string``. Deduplicates by name, base fields first. This is what
    lets an engagement DEFINE custom finding fields at runtime — the dynamic schema.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(name: str, ftype: str, required: bool, label: str) -> None:
        name = re.sub(r"[^a-zA-Z0-9_]", "_", name.strip()).strip("_").lower()
        if not name or name in seen:
            return
        if ftype not in FIELD_TYPE_MAP:
            ftype = "string"
        seen.add(name)
        out.append({"name": name, "type": ftype, "required": bool(required),
                    "label": label or name.replace("_", " ").title()})

    # base fields always come first and keep their required flags
    for spec in DEFAULT_FIELDS:
        _add(spec["name"], spec["type"], spec["required"], spec.get("label", ""))

    for item in (fields or []):
        if isinstance(item, dict):
            _add(str(item.get("name") or ""), str(item.get("type") or "string"),
                 bool(item.get("required")), str(item.get("label") or ""))
            continue
        raw = str(item or "").strip()
        if not raw:
            continue
        required = raw.endswith("!")
        raw = raw.rstrip("!")
        name, _, ftype = raw.partition(":")
        _add(name, (ftype or "string").strip().lower(), required, "")
    return out


def output_schema(fields: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Generate the finding schema descriptor from a field spec (open·kritt ``output_schema``).

    A tiny JSON-Schema-shaped dict: ``{type, required, properties}``. HackPit stays
    dependency-free (open·kritt imports jsonschema); :func:`validate_payload` reads this shape.
    """
    fields = normalize_output_format(fields) if fields else DEFAULT_FIELDS
    props: dict[str, Any] = {}
    required: list[str] = []
    for spec in fields:
        json_type, _check, _coerce = FIELD_TYPE_MAP.get(spec["type"], FIELD_TYPE_MAP["string"])
        prop: dict[str, Any] = {"type": json_type}
        if spec["type"] == "severity":
            prop["enum"] = list(SEVERITY_LEVELS)
        props[spec["name"]] = prop
        if spec.get("required"):
            required.append(spec["name"])
    return {"type": "object", "required": required, "properties": props}


def validate_payload(payload: Any,
                     schema: dict[str, Any] | None = None) -> tuple[bool, list[str]]:
    """Shape-check a finding dict against the schema. Returns (ok, problems).

    Type + required + enum checking only — it does NOT judge whether a finding is *real*
    (that is a post-script / the existing validation gates). Ported from open·kritt's
    ``validate_payload``; kept small and dependency-free.
    """
    schema = schema or output_schema()
    problems: list[str] = []
    if not isinstance(payload, dict):
        return False, ["payload is not a JSON object"]
    for key in schema.get("required", []):
        val = payload.get(key)
        if key not in payload or val is None or (isinstance(val, str) and not val.strip()):
            problems.append(f"missing required field '{key}'")
    for key, spec in schema.get("properties", {}).items():
        if key not in payload or payload[key] is None:
            continue
        val = payload[key]
        want = spec.get("type")
        if want == "string" and not isinstance(val, str):
            problems.append(f"'{key}' must be a string")
        elif want == "array" and not isinstance(val, list):
            problems.append(f"'{key}' must be an array")
        elif want == "number" and not isinstance(val, (int, float)):
            problems.append(f"'{key}' must be a number")
        elif want == "boolean" and not isinstance(val, bool):
            problems.append(f"'{key}' must be a boolean")
        elif want == "object" and not isinstance(val, dict):
            problems.append(f"'{key}' must be an object")
        enum = spec.get("enum")
        if enum and isinstance(val, str) and val not in enum:
            problems.append(f"'{key}' must be one of {enum}")
    return (not problems, problems)


def _kritt_extractor_helper(payload: dict[str, Any], name: str, ftype: str) -> Any:
    """Pull one typed value out of a raw payload, coercing toward its declared type.

    open·kritt's ``_kritt_extractor_helper``: the field-by-field extractor the coercer runs.
    Never raises — a missing or wrong-typed field yields that type's empty value.
    """
    _json, _check, coerce = FIELD_TYPE_MAP.get(ftype, FIELD_TYPE_MAP["string"])
    return coerce(payload.get(name))


def coerce_finding(payload: dict[str, Any],
                   fields: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Normalize an arbitrary producer payload into the canonical finding dict.

    Every declared field is coerced to its type; any key NOT in the schema is preserved under
    ``extra`` (the engagement-defined custom fields). The result is exactly the shape the
    pipeline de-duplicates and ranks, and the shape main.py maps onto ``state.models.Finding``.
    Executes nothing — pure coercion.
    """
    if not isinstance(payload, dict):
        payload = {}
    fields = normalize_output_format(fields) if fields else DEFAULT_FIELDS
    out: dict[str, Any] = {}
    declared: set[str] = set()
    for spec in fields:
        name, ftype = spec["name"], spec["type"]
        declared.add(name)
        out[name] = _kritt_extractor_helper(payload, name, ftype)
    # unknown keys become custom fields. A caller-supplied "extra" map is merged in too.
    extra: dict[str, Any] = dict(payload.get("extra") or {}) if isinstance(
        payload.get("extra"), dict) else {}
    for key, val in payload.items():
        if key in declared or key == "extra":
            continue
        extra[key] = val
    out["extra"] = extra
    return out
