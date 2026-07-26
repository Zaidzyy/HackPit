"""Resolve ONE command / step / run to its detection footprint — what the defender would see.

READ-ONLY ANNOTATION. This module takes a command that has already been (or is about to be)
approved and run through the cockpit's gated executor and answers a purely descriptive question:
*if blue were watching, what would show up?* It never runs anything, never proposes a command,
never touches the executor, the sandbox or the :kali shell. Structurally identical to
``adgraph/techniques.py``: data in, data out.

GROUNDED vs AI_SUGGESTED — the same treatment the kill-chain map and the AD abuse resolver use:

* **grounded** — the curated catalog (:mod:`detection.catalog`) has this command family. Every
  technique, tactic, telemetry line and Sigma rule then comes from MITRE ATT&CK / SigmaHQ, and
  ``grounded=True``.
* **ai_suggested** — the command is not in the catalog (the cockpit lets a human run anything).
  The LLM is asked for the defender's view, and the result is marked ``ai_suggested=True`` so the
  UI can style it as unverified. Even then the answer is RE-GROUNDED before it is returned: an
  ATT&CK id the model invents is dropped unless it exists in :mod:`detection.attck`, and the
  model can never introduce a Sigma rule — only rules already in the curated table are citable.

THE LINE, ENFORCED IN CODE. The footprint describes detection. It must never read as advice on
how to be detected less. :func:`_evasion_prescription` scans every line this module is about to
return — grounded or generated — for prescriptive evasion phrasing ("to avoid detection…",
"to evade…", "so the rule won't fire…"). A generated footprint that trips it is discarded and
replaced with the neutral fallback; a CURATED string that trips it is a bug in the catalog and
raises. ``test_detection_safety.py`` asserts both.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from . import attck, catalog

# Keep the model's answer small and cheap; this is an annotation, not an essay.
_MAX_TOKENS = 650


# --------------------------------------------------------------------------- #
# the line: no evasion prescription, ever
# --------------------------------------------------------------------------- #
# Prescriptive evasion phrasing. These match ADVICE ("to avoid detection, do X"), not
# description ("this is an evasion technique and here is what still records it") — the
# descriptive forms are what the panel exists to say, so they must not trip the guard.
_EVASION_PRESCRIPTION = re.compile(
    r"""(?ix)
    \b(?:
        to\s+(?:avoid|evade|bypass|defeat|reduce|minimi[sz]e|lower)\s+
            (?:detection|logging|alert\w*|telemetry|the\s+rule|the\s+sensor)
      | (?:avoid|evade|bypass|defeat|dodge|slip\s+past)\s+
            (?:the\s+)?(?:detection|edr|av|siem|sensor|logging|sigma\s+rule|this\s+rule)
      | (?:stay|remain|keep)\s+(?:under\s+the\s+radar|undetected|stealthy|quiet\s+by)
      | (?:so|so\s+that|which\s+means)\s+(?:the\s+)?(?:rule|alert|detection|siem|edr)\s+
            (?:will\s+)?(?:not|won'?t|never)\s+(?:fire|trigger|match|alert)
      | (?:disable|blind|silence|turn\s+off|kill)\s+(?:the\s+)?
            (?:sensor|edr|av|logging|auditing|sysmon|etw|amsi)\s+(?:first|before|so)
      | (?:use|prefer|switch\s+to|run)\s+\S+\s+(?:instead|rather)\s+
            (?:to\s+)?(?:avoid|evade|stay|reduce)\b
      | make\s+(?:it|this|the\s+\w+)\s+(?:quieter|stealthier|less\s+detectable)
      | (?:quieter|stealthier|less\s+noisy)\s+(?:alternative|option|approach|way)
    )\b
    """
)


def _evasion_prescription(text: str) -> str | None:
    """The first prescriptive-evasion phrase in ``text``, or None. Used as a guard, not a filter."""
    m = _EVASION_PRESCRIPTION.search(text or "")
    return m.group(0).strip() if m else None


def assert_describes_not_prescribes(strings: Iterable[str], where: str) -> None:
    """Raise if any string tells the reader how to be detected less.

    Applied to the CURATED catalog copy (a hit is a bug to fix in the data) and, in
    :func:`footprint`, to anything the LLM produced (a hit there just discards the answer).
    """
    for s in strings:
        hit = _evasion_prescription(s or "")
        if hit:
            raise ValueError(
                f"{where}: detection copy must DESCRIBE detection, never prescribe evasion "
                f"— found {hit!r} in {s!r}"
            )


# --------------------------------------------------------------------------- #
# shaping
# --------------------------------------------------------------------------- #
def _technique_rows(ids: Iterable[str], source: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for tid in ids:
        if tid in seen:
            continue
        seen.add(tid)
        row = attck.describe(tid)
        row["source"] = source
        rows.append(row)
    return rows


def _tactic_union(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in rows:
        for tac in r.get("tactics", []):
            if tac["id"] not in seen:
                seen.add(tac["id"])
                out.append(tac)
    return out


def _sigma_rows(rules: list[catalog.SigmaRule]) -> list[dict[str, Any]]:
    return [
        {"id": r.id, "title": r.title, "path": r.path, "url": r.url, "level": r.level}
        for r in rules
    ]


SOURCES = {
    "attack": f"{attck.ATTACK_SOURCE} v{attck.ATTACK_VERSION}",
    "attack_attribution": attck.ATTACK_ATTRIBUTION,
    "sigma": f"SigmaHQ open ruleset ({catalog.SIGMA_REPO})",
    "sigma_license": catalog.SIGMA_LICENSE,
}


def _empty(command: str, args: list[str], note: str) -> dict[str, Any]:
    """The honest 'we don't know' footprint — used when there is no catalog hit and no LLM."""
    return {
        "command": command,
        "args": list(args),
        "argv": " ".join([command, *args]).strip(),
        "activity": "",
        "grounded": False,
        "ai_suggested": False,
        "matched_on": "",
        "techniques": [],
        "tactics": [],
        "stealth": {"present": False, "techniques": [], "note": ""},
        "telemetry": [],
        "sigma": [],
        "loudness": {"level": "", "score": 0, "meaning": "", "why": ""},
        "blue_view": "",
        "signals": [],
        "why": note,
        "sources": SOURCES,
    }


# --------------------------------------------------------------------------- #
# the grounded path
# --------------------------------------------------------------------------- #
def _grounded(command: str, args: list[str], match: catalog.Match) -> dict[str, Any]:
    spec = match.spec
    assert spec is not None

    tech_ids = list(spec.techniques)
    sigma_keys = list(spec.sigma)
    telemetry = list(spec.telemetry)
    loud = spec.loudness
    why_bits = [spec.why_rating]

    signal_rows: list[dict[str, Any]] = []
    for sig in match.signals:
        for tid in sig.techniques:
            if tid not in tech_ids:
                tech_ids.append(tid)
        for key in sig.sigma:
            if key not in sigma_keys:
                sigma_keys.append(key)
        telemetry.extend(sig.telemetry)
        if sig.louder:
            loud = catalog.bump(loud)
        signal_rows.append({
            "id": sig.id,
            "label": sig.label,
            "note": sig.note,
            "stealth": sig.stealth,
            "louder": sig.louder,
            "techniques": list(sig.techniques),
        })
        why_bits.append(f"{sig.label}: {sig.note}")

    tech_rows = _technique_rows(tech_ids, "grounded")
    stealth_rows = [t for t in tech_rows if t.get("stealth")]

    out = {
        "command": command,
        "args": list(args),
        "argv": " ".join([command, *args]).strip(),
        "activity": spec.label,
        "grounded": True,
        "ai_suggested": False,
        "matched_on": match.matched_on,
        "spec_key": spec.key,
        "techniques": tech_rows,
        "tactics": _tactic_union(tech_rows),
        "stealth": {
            "present": bool(stealth_rows),
            "techniques": [t["id"] for t in stealth_rows],
            "note": (
                "This action maps to a Stealth / Defense-Impairment technique. ATT&CK tracks it "
                "as a technique in its own right, which means it has its own detections — the "
                "telemetry and rules below are what records it."
            ) if stealth_rows else "",
        },
        "telemetry": _dedupe(telemetry),
        "sigma": _sigma_rows(catalog.sigma_rules(sigma_keys)),
        "loudness": {
            "level": loud,
            "score": catalog.loudness_score(loud),
            "meaning": catalog.LOUDNESS_MEANING.get(loud, ""),
            "why": " ".join(why_bits).strip(),
        },
        "blue_view": spec.blue_view,
        "signals": signal_rows,
        "why": (
            f"Grounded: '{spec.label}' in the curated ATT&CK/SigmaHQ map"
            + (f" (matched on {match.matched_on})" if match.matched_on else "")
            + "."
        ),
        "sources": SOURCES,
    }

    # A curated string that prescribes evasion is a data bug — fail loudly rather than ship it.
    assert_describes_not_prescribes(
        [out["blue_view"], out["loudness"]["why"], out["stealth"]["note"],
         *out["telemetry"], *[s["note"] for s in signal_rows]],
        f"catalog spec {spec.key!r}",
    )
    return out


def _dedupe(items: Iterable[str]) -> list[str]:
    out, seen = [], set()
    for i in items:
        s = str(i).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


# --------------------------------------------------------------------------- #
# the ai_suggested path
# --------------------------------------------------------------------------- #
_LLM_SYSTEM = """\
You are a BLUE-TEAM / detection-engineering analyst annotating a security test for a
purple-team report. You are given one command that a human operator ran (or is about to run)
against a system they are authorized to test.

Describe ONLY what a DEFENDER would observe. You are documenting the detection footprint.

Answer with JSON and nothing else:
{
  "activity": "<what this command does, in defender language, max 8 words>",
  "techniques": ["<MITRE ATT&CK technique IDs, e.g. T1046 or T1003.006>"],
  "telemetry": ["<a specific log/event a defender would see, e.g. 'Windows Security 4688 process creation with this command line'>"],
  "loudness": "quiet|moderate|notable|loud",
  "why_rating": "<one sentence: why that rating, written for the defender>",
  "blue_view": "<one sentence: what appears on the defender's screen>"
}

RULES — these are absolute:
* DESCRIBE detection. NEVER give guidance on avoiding, evading, reducing or delaying it. Do not
  suggest quieter alternatives, flag changes, timing changes, or anything that would make the
  action less visible. If you are tempted to write "to avoid detection…", stop: that is out of
  scope and the answer will be rejected.
* "quiet" means the DEFENDER probably lacks the telemetry, i.e. it is a coverage gap for them to
  close. Say it that way. It is never a recommendation.
* Use real ATT&CK technique IDs only. If you are unsure of an ID, leave the list empty rather
  than guessing.
* Do not name or invent detection rules. Telemetry only.
* No advice to the operator of any kind. No commands.
"""


def _llm_footprint(command: str, args: list[str], context: str, cfg: dict | None) -> dict | None:
    """Ask the LLM for the defender's view of an uncatalogued command. None on any failure."""
    import llm  # local import: the detection package must not hard-depend on the LLM layer

    argv = " ".join([command, *args]).strip()
    user = f"Command: {argv}"
    if context:
        user += f"\nContext: {context}"
    try:
        raw = llm.chat(_LLM_SYSTEM, user, cfg or llm.load_config(), max_tokens=_MAX_TOKENS)
        parsed = llm.extract_json(raw)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _from_llm(command: str, args: list[str], parsed: dict) -> dict[str, Any] | None:
    """Shape + RE-GROUND a model answer. Returns None if it fails the line or is unusable."""
    activity = str(parsed.get("activity") or "").strip()[:120]
    blue_view = str(parsed.get("blue_view") or "").strip()[:400]
    why = str(parsed.get("why_rating") or "").strip()[:400]
    loud = str(parsed.get("loudness") or "").strip().lower()
    if loud not in catalog.LOUDNESS_SCALE:
        loud = "moderate"

    telemetry = _dedupe(
        str(t)[:300] for t in (parsed.get("telemetry") or []) if isinstance(t, (str, int))
    )[:8]

    # Re-ground: an ATT&CK id the model produced is kept only if it is a technique we carry.
    raw_ids = [str(t).strip().upper() for t in (parsed.get("techniques") or []) if t]
    known = [t for t in raw_ids if t in attck.TECHNIQUES]
    dropped = [t for t in raw_ids if t not in attck.TECHNIQUES]

    # THE LINE — anything the model wrote is checked before it is returned.
    for text in [activity, blue_view, why, *telemetry]:
        if _evasion_prescription(text):
            return None

    if not (activity or blue_view or telemetry):
        return None

    tech_rows = _technique_rows(known, "ai_suggested")
    stealth_rows = [t for t in tech_rows if t.get("stealth")]
    note = "AI-suggested: this command is not in the curated ATT&CK/SigmaHQ map, so the footprint "\
           "below is the model's own reading — verify it before relying on it."
    if dropped:
        note += (f" (Dropped {', '.join(dropped)} — not in HackPit's ATT&CK table, so the id "
                 f"could not be resolved to a tactic and telemetry set.)")

    return {
        "command": command,
        "args": list(args),
        "argv": " ".join([command, *args]).strip(),
        "activity": activity,
        "grounded": False,
        "ai_suggested": True,
        "matched_on": "",
        "techniques": tech_rows,
        "tactics": _tactic_union(tech_rows),
        "stealth": {
            "present": bool(stealth_rows),
            "techniques": [t["id"] for t in stealth_rows],
            "note": (
                "This action maps to a Stealth / Defense-Impairment technique — ATT&CK tracks it "
                "as a technique with its own detections."
            ) if stealth_rows else "",
        },
        "telemetry": telemetry,
        # The model may NEVER introduce a detection rule; only the curated table can cite one.
        "sigma": [],
        "loudness": {
            "level": loud,
            "score": catalog.loudness_score(loud),
            "meaning": catalog.LOUDNESS_MEANING.get(loud, ""),
            "why": why,
        },
        "blue_view": blue_view,
        "signals": [],
        "why": note,
        "sources": SOURCES,
    }


# --------------------------------------------------------------------------- #
# THE OFFENSIVE HALF (D10) — the OPSEC channel, kept strictly separate
# --------------------------------------------------------------------------- #
# This is the ONLY place in the package that is allowed to speak about being quieter,
# and it is a SEPARATE channel from the detection footprint. Two rules keep the blue
# view uncontaminated:
#
#   1. `_evasion_prescription` / `assert_describes_not_prescribes` still run over the
#      DETECTION fields, unchanged. Nothing here relaxes that. The blue view is
#      guaranteed identical to before this feature.
#   2. OPSEC content lives only under the `opsec` key. It never merges into
#      blue_view / telemetry / why / signals. `assert_opsec_is_separate` asserts an
#      opsec block carries the honesty invariant and does not leak into detection.
#
# The honesty invariant, mirrored from the blue side: every OPSEC block MUST carry a
# non-empty `still_recorded`. There is no "and now it's invisible" — a quieter path
# that named nothing that still logs it would be an evasion how-to, which this is not.
_OPSEC_LLM_SYSTEM = """\
You are a red-team OPSEC advisor writing the operator-facing half of a purple-team report, for
a security test the operator is AUTHORIZED to run. You are given one command. The blue-team
detection footprint is written separately; your job is the honest tradecraft counterpart.

Answer with JSON and nothing else:
{
  "loud_because": "<the specific thing about this command that generates the signal, one sentence>",
  "quieter": ["<a concrete quieter approach or knob, e.g. 'rate-limit and add jitter'>"],
  "still_recorded": "<what logs this ANYWAY even done the quieter way — REQUIRED, one-two sentences>",
  "tradeoff": "<what the quieter path costs: time, reliability, coverage>"
}

RULES — absolute:
* `still_recorded` is MANDATORY and must be substantive. The honest point of this note is that
  against logging that is actually enabled there is no free lunch. If a quieter approach truly
  escapes ALL telemetry you must still name what a defender could turn on to catch it.
* Advise on tradecraft, not on disabling, tampering with or destroying the defender's telemetry.
  "Turn off Sysmon / clear the log / kill the EDR" is out of scope — that is attacking the
  sensor, not operating quietly, and the answer will be rejected.
* No detection rule names or IDs. No invented ATT&CK IDs.
* Concrete and specific to THIS command. No generic "be careful" filler.
"""

# Attacking the sensor itself is not OPSEC tradecraft — it is a different, louder act with its
# own detections. The OPSEC channel describes operating quietly, never blinding the defender.
_SENSOR_TAMPER = re.compile(
    r"""(?ix)
    \b(?:
        (?:disable|turn\s+off|stop|kill|uninstall|blind|silence|bypass|unhook|tamper\s+with)\s+
            (?:the\s+)?(?:edr|av|antivirus|defender|sysmon|etw|amsi|auditing|audit\s+log\w*|
                          logging|sensor|siem|agent)
      | (?:clear|wipe|delete|flush|purge)\s+(?:the\s+)?(?:event\s+)?log\w*
      | wevtutil\s+cl | Clear-EventLog | Remove-EventLog
      | amsi(?:utils)?\s*\.?\s*bypass | patch\s+amsi
    )\b
    """
)


def _opsec_has_tamper(*texts: str) -> str | None:
    for t in texts:
        m = _SENSOR_TAMPER.search(t or "")
        if m:
            return m.group(0).strip()
    return None


def assert_opsec_is_separate(opsec: dict[str, Any], where: str) -> None:
    """The OPSEC channel's own guard — the counterpart to the never-prescribe guard on blue.

    Asserts the two invariants that let this coexist with the blue view: the honesty marker is
    present, and the note is tradecraft rather than an attack on the defender's sensors.
    """
    if not opsec:
        return
    if not str(opsec.get("still_recorded") or "").strip():
        raise ValueError(f"{where}: an OPSEC note must name what still records the activity")
    hit = _opsec_has_tamper(
        opsec.get("loud_because", ""), opsec.get("still_recorded", ""),
        opsec.get("tradeoff", ""), *(opsec.get("quieter") or []),
    )
    if hit:
        raise ValueError(
            f"{where}: OPSEC is operating quietly, not blinding the defender — found "
            f"sensor-tampering phrasing {hit!r}"
        )


def _opsec_grounded(spec_key: str) -> dict[str, Any] | None:
    note = catalog.opsec_for(spec_key)
    if note is None:
        return None
    out = {
        "grounded": True,
        "ai_suggested": False,
        "loud_because": note.loud_because,
        "quieter": list(note.quieter),
        "still_recorded": note.still_recorded,
        "tradeoff": note.tradeoff,
    }
    # A curated OPSEC note that violated the channel's own rules is a data bug — raise.
    assert_opsec_is_separate(out, f"OPSEC note {spec_key!r}")
    return out


def _opsec_from_llm(command: str, args: list[str], cfg: dict | None) -> dict[str, Any] | None:
    """The ai_suggested OPSEC reading for an uncatalogued command. None on any failure."""
    import llm

    argv = " ".join([command, *args]).strip()
    try:
        raw = llm.chat(_OPSEC_LLM_SYSTEM, f"Command: {argv}", cfg or llm.load_config(),
                       max_tokens=_MAX_TOKENS)
        parsed = llm.extract_json(raw)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    quieter = _dedupe(str(q)[:300] for q in (parsed.get("quieter") or [])
                      if isinstance(q, (str, int)))[:6]
    out = {
        "grounded": False,
        "ai_suggested": True,
        "loud_because": str(parsed.get("loud_because") or "").strip()[:400],
        "quieter": quieter,
        "still_recorded": str(parsed.get("still_recorded") or "").strip()[:400],
        "tradeoff": str(parsed.get("tradeoff") or "").strip()[:400],
    }
    if not (out["quieter"] or out["loud_because"]):
        return None
    # Model output must satisfy the channel's guard or it is discarded (not raised).
    try:
        assert_opsec_is_separate(out, "ai_suggested OPSEC")
    except ValueError:
        return None
    return out


def _attach_opsec(fp: dict[str, Any], command: str, args: list[str],
                  allow_llm: bool, cfg: dict | None) -> dict[str, Any]:
    """Add the `opsec` block to a footprint without touching any detection field."""
    opsec = None
    key = fp.get("spec_key")
    if key:
        opsec = _opsec_grounded(key)
    if opsec is None and allow_llm and fp.get("activity"):
        opsec = _opsec_from_llm(command, args, cfg)
    fp["opsec"] = opsec  # None is a valid, explicit "no OPSEC note for this command"
    return fp


# --------------------------------------------------------------------------- #
# the entry points
# --------------------------------------------------------------------------- #
def footprint(
    command: str,
    args: list[str] | None = None,
    *,
    context: str = "",
    allow_llm: bool = True,
    cfg: dict | None = None,
    include_opsec: bool = False,
) -> dict[str, Any]:
    """The detection footprint for one command.

    Grounded from the curated map when it covers the command; otherwise (``allow_llm``) the LLM
    is asked and the answer is marked ``ai_suggested`` after being re-grounded and checked
    against the describe-not-prescribe rule. Never executes anything.

    ``include_opsec`` (D10) additionally attaches the OFFENSIVE half — an ``opsec`` block with
    the quieter tradecraft and, mandatorily, what still records the activity. It is OFF by
    default so every existing caller (tagging, reports, run annotation) is byte-for-byte
    unchanged; the purple-team panel opts in. The blue-team fields are identical either way.
    """
    cmd = str(command or "").strip()
    argv = [str(a) for a in (args or [])]
    if not cmd:
        return _empty(cmd, argv, "No command to annotate.")

    match = catalog.lookup(cmd, argv)
    if match.spec is not None:
        fp = _grounded(cmd, argv, match)
    else:
        fp = None
        if allow_llm:
            parsed = _llm_footprint(cmd, argv, context, cfg)
            if parsed:
                shaped = _from_llm(cmd, argv, parsed)
                if shaped:
                    # Argument signals still apply to an uncatalogued command.
                    if match.signals:
                        shaped = _apply_signals_to_ai(shaped, match.signals)
                    fp = shaped
        if fp is None:
            fp = _empty(
                cmd, argv,
                "Not in the curated ATT&CK/SigmaHQ map, and no model reading was available. "
                "Treat the footprint as unknown rather than absent.",
            )

    if include_opsec:
        fp = _attach_opsec(fp, cmd, argv, allow_llm, cfg)
    return fp


def _apply_signals_to_ai(shaped: dict[str, Any], signals: tuple[catalog.ArgSignal, ...]) -> dict:
    """Fold the curated argument signals into an ai_suggested footprint.

    The signals themselves ARE grounded (they carry real ATT&CK ids + curated Sigma rules), so
    a command the catalog does not know can still get a grounded stealth/escalation annotation.
    """
    tech_ids = [t["id"] for t in shaped["techniques"]]
    sigma_keys: list[str] = []
    for sig in signals:
        for tid in sig.techniques:
            if tid not in tech_ids:
                tech_ids.append(tid)
        sigma_keys.extend(sig.sigma)
        shaped["telemetry"] = _dedupe([*shaped["telemetry"], *sig.telemetry])
        if sig.louder:
            shaped["loudness"]["level"] = catalog.bump(shaped["loudness"]["level"])
        shaped["signals"].append({
            "id": sig.id, "label": sig.label, "note": sig.note,
            "stealth": sig.stealth, "louder": sig.louder, "techniques": list(sig.techniques),
        })

    grounded_ids = {t for s in signals for t in s.techniques}
    rows = []
    for tid in tech_ids:
        row = attck.describe(tid)
        row["source"] = "grounded" if tid in grounded_ids else "ai_suggested"
        rows.append(row)
    shaped["techniques"] = rows
    shaped["tactics"] = _tactic_union(rows)
    stealth_rows = [t for t in rows if t.get("stealth")]
    shaped["stealth"] = {
        "present": bool(stealth_rows),
        "techniques": [t["id"] for t in stealth_rows],
        "note": ("This action maps to a Stealth / Defense-Impairment technique — ATT&CK tracks "
                 "it as a technique with its own detections.") if stealth_rows else "",
    }
    shaped["sigma"] = _sigma_rows(catalog.sigma_rules(sigma_keys))
    shaped["loudness"]["score"] = catalog.loudness_score(shaped["loudness"]["level"])
    shaped["loudness"]["meaning"] = catalog.LOUDNESS_MEANING.get(shaped["loudness"]["level"], "")
    return shaped


def first_command_line(block: str) -> str:
    """The first REAL command line in a block — comments and blanks skipped.

    KB and catalog commands routinely arrive as a small script: a ``# what this does`` comment,
    then the command, sometimes over continuation lines. Annotating the comment would be
    meaningless (and would push every such block down the ai_suggested path), so the first
    non-comment, non-blank line is the actor.
    """
    lines = str(block or "").splitlines()
    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # fold shell line-continuations into one command line
        while line.endswith("\\") and i + 1 < len(lines):
            i += 1
            line = line[:-1].rstrip() + " " + lines[i].strip()
        return line
    return ""


def footprint_for_argv(argv: list[str] | str, **kw) -> dict[str, Any]:
    """Footprint for a whole command line — ``['nmap','-sV','host']`` or ``'nmap -sV host'``.

    A multi-line block is accepted: the first real command line in it is what gets annotated.
    """
    if isinstance(argv, str):
        line = first_command_line(argv)
        try:
            import shlex
            parts = shlex.split(line)
        except ValueError:      # unbalanced quotes in a hand-written step command
            parts = line.split()
    else:
        parts = [str(a) for a in argv]
    if not parts:
        return _empty("", [], "No command to annotate.")
    return footprint(parts[0], parts[1:], **kw)


def footprint_for_run(run: dict[str, Any] | Any, **kw) -> dict[str, Any]:
    """Footprint for a cockpit RunRecord (dict or model). Annotation only — reads, never runs."""
    if hasattr(run, "model_dump"):
        run = run.model_dump()
    run = dict(run or {})
    ctx = kw.pop("context", "")
    target = run.get("target") or ""
    mode = run.get("mode") or ""
    if target and "target" not in ctx:
        ctx = (ctx + f" target={target} mode={mode}").strip()
    return footprint(run.get("command") or "", run.get("args") or [], context=ctx, **kw)


def footprint_for_step(step: dict[str, Any] | Any, **kw) -> dict[str, Any]:
    """Footprint for one attack-path step — annotates its FIRST command.

    A step's commands are its plan; the footprint answers what running that plan would look
    like from the defender's side. Nothing here runs the command.
    """
    if hasattr(step, "model_dump"):
        step = step.model_dump()
    step = dict(step or {})
    first = ""
    for c in (step.get("commands") or []):
        raw = (c.get("cmd") if isinstance(c, dict) else getattr(c, "cmd", "")) or ""
        first = first_command_line(str(raw))
        if first:
            break
    if not first:
        return _empty("", [], "This step has no command to annotate.")
    ctx = kw.pop("context", "") or str(step.get("title") or "")
    return footprint_for_argv(first, context=ctx, **kw)


__all__ = [
    "footprint", "footprint_for_argv", "footprint_for_run", "footprint_for_step",
    "first_command_line", "assert_describes_not_prescribes", "SOURCES",
]
