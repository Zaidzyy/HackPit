"""SAFETY INVARIANTS for the detection-footprint panel (D7).

The panel is a READ-ONLY ANNOTATION LAYER over work the cockpit already gates. It must add no
new way to run anything, weaken no gate, and — the invariant that is specific to this feature —
it must DESCRIBE detection without ever prescribing evasion. These tests fail loudly if any of
that weakens:

  1. NO EXECUTION IN detection/: no module in the package imports subprocess / Popen /
     os.system / docker, or calls the executor's run path. It annotates data only. (Same
     structural lock the AD graph has — see test_adgraph_safety.py.)
  2. ZERO :kali PATH: no detection module references run_kali or the open :kali container.
  3. NO NEW CAPABILITY: every detection route is read-only; the package exposes no approve,
     exec, or write path, and nothing in it constructs an ExecRequest.
  4. THE COCKPIT IS UNTOUCHED: no module in the cockpit package imports or references detection.
     The execution layer does not know this feature exists, so it cannot be changed by it.
  5. THE LINE — DESCRIBES, NEVER PRESCRIBES: every curated string the panel can emit (specs,
     signals, loudness copy) and every defensive KB page passes the evasion-prescription guard;
     a model answer that trips it is DISCARDED rather than shown.
  6. THE KB PAGES CARRY NO COMMANDS: the defensive reference pages have no code blocks, so the
     attack-path composer can never surface one as a runnable step.
  7. LAB + ENGAGEMENT UNCHANGED: importing and exercising detection does not alter the lab
     target-lock wording, the gate order, or engagement's never-auto-run rule.

Hermetic: no Docker, no LLM, no network. Run:  python test_detection_safety.py
"""
from __future__ import annotations

import json
from pathlib import Path

from cockpit import executor as E
from cockpit.models import EngagementRecord, ExecRequest
from detection import attck as A
from detection import catalog as C
from detection import resolver as R
from detection import router as RT
from detection import tagging as T

_DETECTION_MODULES = [A, C, R, RT, T]

# Tokens that would mean a module can execute something itself.
_EXEC_TOKENS = ["subprocess", "Popen", "os.system", "docker exec", "pty.spawn", "os.exec",
                "os.popen", "commands.getoutput"]
_KALI_TOKENS = ["run_kali", "KALI_OPEN", "cockpit.kali", "from .kali", "/cockpit/kali"]
# The executor's run entrypoints — detection must never call them.
_RUN_TOKENS = ["iter_run(", "run_command(", ".Popen(", "ExecRequest("]

REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORED_KB = REPO_ROOT / "pipeline" / "authored" / "authored_entries.jsonl"


def _src(mod) -> str:
    return Path(mod.__file__).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
def test_no_execution_in_detection() -> None:
    for mod in _DETECTION_MODULES:
        src = _src(mod)
        for tok in _EXEC_TOKENS:
            assert tok not in src, f"{mod.__name__} must not execute anything (found {tok!r})"
        for tok in _RUN_TOKENS:
            assert tok not in src, f"{mod.__name__} must not touch the executor run path ({tok!r})"
    print("  no detection module executes anything / calls the executor run path: PASS")


def test_zero_kali_path() -> None:
    for mod in _DETECTION_MODULES:
        src = _src(mod)
        for tok in _KALI_TOKENS:
            assert tok not in src, f"{mod.__name__} must have ZERO :kali path (found {tok!r})"
        assert not hasattr(mod, "run_kali") and not hasattr(mod, "kali"), \
            f"{mod.__name__} must not reference :kali"
    print("  detection has ZERO :kali path: PASS")


def test_routes_are_read_only() -> None:
    """Every detection route is a read. No route approves, executes, or persists anything."""
    unsafe = []
    for route in RT.router.routes:
        methods = set(getattr(route, "methods", set()) or set())
        path = getattr(route, "path", "")
        if methods - {"GET", "POST", "HEAD", "OPTIONS"}:
            unsafe.append(f"{path}: unexpected method {methods}")
        # the POST routes exist only because a command line is too big for a query string
        if "POST" in methods and path not in ("/detection/footprint", "/detection/footprint/step",
                                              "/detection/tag"):
            unsafe.append(f"{path}: unexpected POST route")
    assert not unsafe, unsafe

    src = _src(RT)
    for tok in ("approved=True", "save_run", "write_stdin", "start_session", "engagement.enter"):
        assert tok not in src, f"the detection router must not {tok!r}"
    print(f"  all {len(RT.router.routes)} detection routes are read-only annotation: PASS")


def test_cockpit_package_is_untouched() -> None:
    """The execution layer must not know this feature exists — so it cannot be changed by it."""
    cockpit_dir = Path(__file__).resolve().parent / "cockpit"
    offenders = []
    for py in sorted(cockpit_dir.glob("*.py")):
        src = py.read_text(encoding="utf-8")
        if "detection" in src.replace("# ", "").lower():
            for i, line in enumerate(src.splitlines(), 1):
                low = line.lower()
                if "detection" in low and not low.lstrip().startswith("#"):
                    offenders.append(f"{py.name}:{i}: {line.strip()}")
    assert not offenders, "the cockpit package must not reference detection:\n" + "\n".join(offenders)
    print("  the cockpit package is untouched by this feature (no import, no reference): PASS")


# --------------------------------------------------------------------------- #
# THE LINE
# --------------------------------------------------------------------------- #
def test_curated_copy_describes_never_prescribes() -> None:
    """Every string the panel can emit from the curated map is checked against the guard.

    A hit here is a DATA bug — copy that drifted toward "to avoid detection, do X" — and it
    fails the build rather than shipping.
    """
    checked = 0
    for spec in C.SPECS.values():
        strings = [spec.label, spec.blue_view, spec.why_rating, *spec.telemetry]
        R.assert_describes_not_prescribes(strings, f"spec {spec.key!r}")
        checked += len(strings)
    for sig in C.ARG_SIGNALS:
        strings = [sig.label, sig.note, *sig.telemetry]
        R.assert_describes_not_prescribes(strings, f"signal {sig.id!r}")
        checked += len(strings)
    R.assert_describes_not_prescribes(list(C.LOUDNESS_MEANING.values()), "loudness scale")
    checked += len(C.LOUDNESS_MEANING)

    # and every grounded footprint the catalog can produce (the resolver re-checks on the way out)
    for spec in C.SPECS.values():
        R._grounded("x", [], C.Match(spec=spec, signals=tuple(C.ARG_SIGNALS), matched_on="tool"))
    print(f"  {checked} curated strings + all {len(C.SPECS)} grounded footprints "
          f"DESCRIBE detection, none prescribe evasion: PASS")


def test_guard_actually_catches_prescription() -> None:
    """The guard is only worth anything if it fires. Prove it on the phrasings we forbid."""
    must_catch = [
        "To avoid detection, use a slower scan.",
        "Use --tamper instead to evade the WAF rule.",
        "Disable the sensor first so the rule will not fire.",
        "This is a quieter alternative to secretsdump.",
        "Make it stealthier by encoding the command.",
        "Stay under the radar by pacing the requests.",
    ]
    for text in must_catch:
        assert R._evasion_prescription(text), f"guard MISSED a prescription: {text!r}"

    # ...and does not fire on the descriptive statements the panel exists to make
    must_allow = [
        "This is loud: the scan shape is what NSM tooling is built to spot.",
        "ATT&CK classifies source spoofing as Masquerading (Stealth, TA0005).",
        "Detection rules match the encoding itself, so this is often a stronger signal.",
        "Quiet: ATT&CK lists no target-side detection strategy, which is a defender gap.",
        "Clearing a log announces that a log was cleared.",
    ]
    for text in must_allow:
        assert not R._evasion_prescription(text), f"guard FALSE-POSITIVED on: {text!r}"
    print(f"  the guard catches all {len(must_catch)} forbidden phrasings and none of the "
          f"{len(must_allow)} descriptive ones: PASS")


def test_model_prescription_is_discarded() -> None:
    """A model answer that drifts into evasion advice is thrown away, not rendered."""
    import llm

    bad = json.dumps({
        "activity": "Port scan", "techniques": ["T1046"], "telemetry": ["firewall logs"],
        "loudness": "quiet",
        "why_rating": "Use -T1 timing to avoid detection by the IDS.",
        "blue_view": "Little is seen.",
    })
    orig = llm.chat
    try:
        llm.chat = lambda system, user, cfg, max_tokens=0: bad
        fp = R.footprint("some-unknown-scanner", ["-x"])
    finally:
        llm.chat = orig
    assert fp["ai_suggested"] is False, "a prescriptive answer must NOT be shown as a footprint"
    assert fp["techniques"] == [] and fp["blue_view"] == ""
    assert "unknown" in fp["why"].lower()
    print("  a model answer containing evasion advice is DISCARDED, not rendered: PASS")


def test_defensive_kb_pages_carry_no_commands() -> None:
    """The evasion-taxonomy pages are knowledge, not recipes.

    attack_path.entry_commands() lifts commands out of step code blocks, so a page with none can
    never be surfaced as a runnable attack-path step.
    """
    assert AUTHORED_KB.exists(), AUTHORED_KB
    rows = [json.loads(l) for l in AUTHORED_KB.read_text(encoding="utf-8").splitlines() if l.strip()]
    pages = [r for r in rows if (r.get("meta") or {}).get("type") == "detection-reference"]
    assert pages, "the defensive reference pages are missing from the authored KB"

    import attack_path

    for page in pages:
        n_code = sum(len(s.get("code") or []) for s in page.get("steps") or [])
        assert n_code == 0, f"{page['id']} carries {n_code} command block(s) — must carry none"
        assert not attack_path.entry_commands(page), \
            f"{page['id']} is step-eligible; a detection-reference page must never be"
        assert page.get("category") == "reference", page["id"]
        R.assert_describes_not_prescribes(
            [page.get("summary", ""), page.get("body_md", "")], f"KB page {page['id']!r}"
        )
    print(f"  all {len(pages)} defensive KB pages carry NO commands and prescribe no evasion: PASS")


# --------------------------------------------------------------------------- #
# the gates are unchanged
# --------------------------------------------------------------------------- #
def test_lab_mode_unchanged() -> None:
    ok, _ = E.check_target_lock(["-sV", "hackpit-lab-target"], "nmap")
    assert ok
    ok, reason = E.check_target_lock(["-sV", "dc01.sevenkingdoms.local"], "nmap")
    assert not ok and reason == "target 'dc01.sevenkingdoms.local' is not the lab — only the lab is allowed"
    lab = ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=False)
    rej = E.validate_request(lab)
    assert rej is not None and rej.gate == "approval", "lab gate order unchanged (target->approval)"
    print("  LAB target-lock wording + gate order byte-for-byte unchanged: PASS")


def test_engagement_never_auto_run_unchanged() -> None:
    eng = EngagementRecord(
        engagement_id="eng-detsafe0000", target="app.example.com", authorization="ok", active=True,
        entered_at="2026-07-25T00:00:00+00:00", scope="app.example.com",
        scope_include=["app.example.com"], allowed_hosts=["app.example.com"],
    )
    orig = E.engagement.get_active
    E.engagement.get_active = lambda _id: eng  # type: ignore[assignment]
    try:
        # annotating a command must not make it runnable
        req = ExecRequest(command="nmap", args=["-sV", "app.example.com"], approved=False,
                          engagement_id=eng.engagement_id)
        R.footprint_for_run(req.model_dump() | {"target": eng.target}, allow_llm=False)
        rej = E.validate_request(req)
        assert rej is not None and rej.gate == "approval", rej
        off = ExecRequest(command="nmap", args=["-sV", "evil.example.net"], approved=True,
                          engagement_id=eng.engagement_id)
        rej2 = E.validate_request(off)
        assert rej2 is not None and rej2.gate == "target", rej2
    finally:
        E.engagement.get_active = orig
    print("  ENGAGEMENT never-auto-run + scope-lock unchanged after annotating: PASS")


def test_annotation_returns_data_not_execution() -> None:
    """The resolver hands back a description. It holds no command to run and starts nothing."""
    fp = R.footprint("impacket-secretsdump", ["-just-dc", "d/u:p@dc01"], allow_llm=False)
    assert isinstance(fp, dict) and fp["grounded"]
    # a footprint has no runnable surface at all — unlike the AD technique resolver, which
    # deliberately returns a command for the human to approve, this returns none.
    assert "commands" not in fp and "command_to_run" not in fp
    assert "request" not in fp and "approved" not in fp
    print("  a footprint is pure description — it carries no runnable command: PASS")


# --------------------------------------------------------------------------- #
# THE OFFENSIVE HALF (D10) — the OPSEC channel must not weaken the blue view
# --------------------------------------------------------------------------- #
def test_blue_view_is_byte_identical_with_and_without_opsec() -> None:
    """Adding the offensive half must not change a single blue-team field.

    This is the load-bearing D10 invariant: 'keep the blue-team view, add the other half'.
    Every detection field must be identical whether or not include_opsec is set.
    """
    for spec in C.SPECS.values():
        argv = spec.label  # any argv; we compare the two calls to each other
        blue = R.footprint("nmap" if spec.key == "portscan" else "x", [], allow_llm=False)
        both = R.footprint("nmap" if spec.key == "portscan" else "x", [],
                           allow_llm=False, include_opsec=True)
        blue_no_opsec = {k: v for k, v in both.items() if k != "opsec"}
        assert blue == blue_no_opsec, "include_opsec changed a blue-team field"
        break  # one representative pair is enough; the assert is exact
    # And the default call carries no opsec key at all — existing callers are unchanged.
    fp = R.footprint("impacket-secretsdump", ["-just-dc"], allow_llm=False)
    assert "opsec" not in fp, "include_opsec defaults off; the key must be absent by default"
    print("  blue-team fields are byte-identical with/without opsec; default omits it: PASS")


def test_every_curated_opsec_note_carries_the_honesty_marker() -> None:
    """Each OPSEC note must name what still records the activity (no 'now invisible')."""
    assert C.OPSEC, "expected curated OPSEC notes"
    for key, note in C.OPSEC.items():
        assert key in C.SPECS, f"OPSEC note {key!r} has no matching footprint spec"
        assert note.still_recorded.strip(), f"{key}: still_recorded is mandatory"
        assert note.quieter, f"{key}: a note with no quieter approach is pointless"
        # Its own guard must pass on curated data (a failure here is a data bug).
        R.assert_opsec_is_separate(
            {"loud_because": note.loud_because, "quieter": list(note.quieter),
             "still_recorded": note.still_recorded, "tradeoff": note.tradeoff},
            f"OPSEC {key!r}",
        )
    print(f"  all {len(C.OPSEC)} curated OPSEC notes carry still_recorded + pass the guard: PASS")

    # #4 backfill completeness: every #3 persistence (TA0003) spec must have a note.
    persist_specs = [k for k in C.SPECS if k.startswith("persist_")]
    assert persist_specs, "expected #3 persistence specs"
    missing = [k for k in persist_specs if k not in C.OPSEC]
    assert not missing, f"persistence specs with no OPSEC note (backfill incomplete): {missing}"
    print(f"  all {len(persist_specs)} persistence specs carry an OPSEC note: PASS")


def test_opsec_guard_allows_prescriptive_evasion_with_honesty() -> None:
    """New contract (build #4, D-guard): prescriptive evasion — including in-process
    sensor-blinding (AMSI-patch, ETW-blind) — is ALLOWED as long as every note names what
    still records it. The one surviving invariant is the honesty marker."""
    now_allowed = [
        {"loud_because": "AMSI scans the script as it loads.",
         "quieter": ["Patch AMSI in-process before loading the script."],
         "still_recorded": "The patch itself is a known-bad memory write Sysmon/EDR image-load "
                           "and AMSI-bypass rules flag; the process still starts.",
         "tradeoff": "Fragile across patch levels; a failed patch is louder than none."},
        {"loud_because": "ETW feeds the EDR's script/telemetry pipeline.",
         "quieter": ["Blind ETW for the current process."],
         "still_recorded": "ETW-tampering has its own detections; the parent process, its image "
                           "load and network are still recorded.",
         "tradeoff": "Process-scoped only; does not stop kernel callbacks."},
    ]
    for op in now_allowed:
        R.assert_opsec_is_separate(op, "test")   # must NOT raise
    # The one surviving invariant: a note with no honesty marker is rejected.
    try:
        R.assert_opsec_is_separate(
            {"loud_because": "x", "quieter": ["patch amsi"], "still_recorded": "  ", "tradeoff": ""},
            "test",
        )
        assert False, "a note missing still_recorded must be rejected"
    except ValueError:
        pass
    print("  OPSEC guard allows prescriptive evasion; still_recorded stays mandatory: PASS")


def test_model_opsec_kept_with_honesty_marker() -> None:
    """An ai_suggested evasion note is KEPT when it carries the honesty marker (build #4),
    and DROPPED when it does not."""
    import llm

    honest = json.dumps({
        "loud_because": "AMSI scans the script as it loads.",
        "quieter": ["Patch AMSI in-process before loading the script."],
        "still_recorded": "The patch is a known-bad memory write EDR/AMSI-bypass rules flag; "
                          "the process still starts.",
        "tradeoff": "Fragile across patch levels.",
    })
    dishonest = json.dumps({
        "loud_because": "AMSI scans the script as it loads.",
        "quieter": ["Patch AMSI in-process before loading the script."],
        "still_recorded": "",
        "tradeoff": "None.",
    })
    # `footprint(include_opsec=True)` makes TWO model calls with two different system prompts —
    # the blue footprint first, then the OPSEC note (and the OPSEC one is only attempted when
    # the footprint came back usable). Answer each with the payload it actually asked for.
    blue = json.dumps({
        "activity": "Runs an uncatalogued binary.",
        "blue_view": "A new process appears under the shell with an unfamiliar image name.",
        "why_rating": "Process creation is recorded by default on an audited host.",
        "loudness": "moderate",
        "telemetry": ["Process creation event carrying the image path and command line."],
        "techniques": [],
    })

    def _answer(opsec_reply):
        def chat(system, user, cfg, max_tokens=0):
            return opsec_reply if "OPSEC advisor" in system else blue
        return chat

    orig = llm.chat
    try:
        llm.chat = _answer(honest)
        kept = R.footprint("some-unknown-tool", ["-x"], include_opsec=True)
        llm.chat = _answer(dishonest)
        dropped = R.footprint("some-unknown-tool", ["-x"], include_opsec=True)
    finally:
        llm.chat = orig
    assert kept["ai_suggested"] is True, "the blue footprint should have come from the model"
    assert kept.get("opsec") and kept["opsec"]["ai_suggested"] is True, \
        "an honest ai_suggested evasion note must be kept"
    assert dropped.get("opsec") is None, "a note with no still_recorded must be dropped"
    print("  a model evasion note is kept iff it carries the honesty marker: PASS")


def test_opsec_never_leaks_into_the_blue_fields() -> None:
    """OPSEC text lives only under the `opsec` key — never in blue_view/telemetry/why."""
    fp = R.footprint("nmap", ["-sS", "-p-", "10.0.0.1"], allow_llm=False, include_opsec=True)
    assert fp.get("opsec"), "expected a grounded OPSEC note for a port scan"
    quieter_text = " ".join(fp["opsec"]["quieter"]).lower()
    blue_blob = " ".join([
        fp["blue_view"], fp["loudness"]["why"], fp["why"], *fp["telemetry"],
        *[s["note"] for s in fp["signals"]],
    ]).lower()
    # The distinctive quieter phrasing must not have bled into the blue copy.
    assert "quieter" not in blue_blob and "--scan-delay" not in blue_blob
    # And the blue copy still passes the never-prescribe guard even with opsec attached.
    R.assert_describes_not_prescribes(
        [fp["blue_view"], fp["loudness"]["why"], fp["why"], *fp["telemetry"]],
        "blue fields with opsec attached",
    )
    print("  OPSEC content stays in its own channel; blue copy still passes the guard: PASS")


if __name__ == "__main__":
    test_no_execution_in_detection()
    test_zero_kali_path()
    test_routes_are_read_only()
    test_cockpit_package_is_untouched()
    test_curated_copy_describes_never_prescribes()
    test_guard_actually_catches_prescription()
    test_model_prescription_is_discarded()
    test_defensive_kb_pages_carry_no_commands()
    test_lab_mode_unchanged()
    test_engagement_never_auto_run_unchanged()
    test_annotation_returns_data_not_execution()
    test_blue_view_is_byte_identical_with_and_without_opsec()
    test_every_curated_opsec_note_carries_the_honesty_marker()
    test_opsec_guard_allows_prescriptive_evasion_with_honesty()
    test_model_opsec_kept_with_honesty_marker()
    test_opsec_never_leaks_into_the_blue_fields()
    print("ALL detection safety-invariant tests pass")
