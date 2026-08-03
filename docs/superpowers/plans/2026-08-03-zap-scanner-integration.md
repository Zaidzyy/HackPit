# ZAP Scanner Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OWASP ZAP as HackPit's first active web vulnerability scanner, driven as an ordinary gated command so it inherits every existing safety gate unchanged.

**Architecture:** ZAP is modelled on nuclei — a catalogued tool the executor gates and the state ingest parses. Scans run via ZAP's packaged scan scripts (`zap-baseline.py`, `zap-full-scan.py`) through `POST /cockpit/exec`. No daemon, no REST API, no new module, no new endpoint, no frontend. Findings reach the state model through the existing `STDOUT_PARSERS` / `FILE_PARSERS` registries.

**Tech Stack:** Python 3 (stdlib `json` only — no new dependency), Docker (Kali rolling base), existing HackPit backend packages (`cockpit`, `state`, `arsenal`, `detection`).

**Spec:** `docs/superpowers/specs/2026-08-03-zap-scanner-integration-design.md`

## Global Constraints

Every task's requirements implicitly include this section.

- **`backend/arsenal/tools.json` is hand-formatted with CRLF line endings.** Patch it in place with a text edit. NEVER rewrite it via `json.dump` / `json.dumps` — that reformats the whole file and produces an unreviewable diff.
- **Never name a test file `test_scans.py`.** That name and `backend/test_support/scans.py` are the shared source scanner, which ten safety locks depend on. This build's tests are `backend/test_zap.py` and `backend/test_zap_safety.py`.
- **TWO NORMALISERS EXIST AND THEY DIFFER.** This is the single highest-risk detail in this plan:
  - `cockpit/allowlist.py::_tool_name()` — basename, lowercase, strips `.py` / `.exe` / `.ps1`, strips `impacket-` prefix. `zap-full-scan.py` → **`zap-full-scan`**
  - `state/ingest.py::program_name()` — basename, lowercase, strips `.exe` ONLY, strips `impacket-` prefix. `zap-full-scan.py` → **`zap-full-scan.py`**

  So: danger-heuristic sets are keyed **without** `.py`; parser registry keys are keyed **with** `.py`; `test_arsenal_safety` buckets are keyed as the catalog spells them (**with** `.py`, matching existing entries `jwt_tool.py`, `testssl.sh`, `linpeas.sh`).
- **`cockpit` and `arsenal` may not reference each other in either direction** — substring-enforced, comments count.
- **Ingestion is additive enrichment and never gates a run.** A parser must never raise; return an empty `Parsed` on any malformed input.
- **The assessment lands in the SAME commit** as the change it describes: edit `docs/ASSESSMENT-2026-07-26.md`, then run `python docs/build-assessment.py`. Verify against the generated **HTML** — the PDF cannot be grepped (Edge subsets fonts to glyph IDs).
- **Windows dev host.** Use `sh backend/run_safety_tests.sh` via the Bash tool, or the backend venv Python directly. Tests are plain `python test_x.py` scripts with `if __name__ == "__main__":` blocks, not pytest.
- **No permitted-command allowlist exists.** Despite the module name, `cockpit/allowlist.py` has no `ALLOWED` set — the lab gates are target-lock → approval → danger heuristic → isolation. ZAP does not need to be added to any permit list to run.

---

### Task 1: ZAP report parser and registry wiring

Pure Python, no Docker needed. Done first so the rest has something to build on.

**Files:**
- Modify: `backend/state/parsers.py` (add `_ZAP_RISK`, `_zap_report()`, `parse_zap()`; extend `FILE_PARSERS` at line ~314 and `STDOUT_PARSERS` at line ~319)
- Create: `backend/test_zap.py`

**Interfaces:**
- Consumes: `Parsed`, `Finding`, `Endpoint` from `backend/state/parsers.py` and `backend/state/models.py` (already imported in that module).
- Produces: `parse_zap(text: str, session_id: str, run_id: str | None = None) -> Parsed`. Task 4 verifies the registry keys against the built image.

**Why this parser does its own JSON extraction:** `_json_objects()` (parsers.py:67) tries a whole-document parse, then falls back to line-delimited. ZAP's scan scripts print progress lines before a pretty-printed multi-line report, so the document does not parse whole AND no single line parses either. Both branches fail. `_json_objects()` must NOT be modified — every existing parser depends on its current behaviour.

- [ ] **Step 1: Write the failing test**

Create `backend/test_zap.py`:

```python
"""ZAP report parser regression tests.  Run:  python test_zap.py

NOT named test_scans.py — that name belongs to the shared source scanner.
"""

from __future__ import annotations

from state import parsers

SESSION = "s-zap-test"

# A real ZAP traditional-JSON report, wrapped in the progress noise the scan scripts print
# around it. riskcode is a STRING in ZAP's output, not an int.
NOISY_REPORT = """\
Total of 3 URLs
PASS: Vulnerable JS Library [10003]
WARN-NEW: SQL Injection [40018] x 1
{
  "@programName": "ZAP",
  "@version": "2.14.0",
  "site": [
    {
      "@name": "http://lab.local",
      "@host": "lab.local",
      "@port": "80",
      "alerts": [
        {
          "pluginid": "40018",
          "name": "SQL Injection",
          "riskcode": "3",
          "desc": "<p>SQL injection may be possible.</p>",
          "instances": [
            {
              "uri": "http://lab.local/search",
              "method": "GET",
              "param": "q",
              "attack": "' OR '1'='1",
              "evidence": "syntax error"
            }
          ]
        },
        {
          "pluginid": "10038",
          "name": "Content Security Policy Header Not Set",
          "riskcode": "1",
          "instances": [
            {"uri": "http://lab.local/", "method": "GET", "param": ""}
          ]
        },
        {
          "pluginid": "10096",
          "name": "Timestamp Disclosure",
          "riskcode": "0",
          "instances": [{"uri": "http://lab.local/app.js", "method": "GET", "param": ""}]
        },
        {
          "pluginid": "40012",
          "name": "Cross Site Scripting (Reflected)",
          "riskcode": "2",
          "instances": [{"uri": "http://lab.local/x", "method": "POST", "param": "name"}]
        }
      ]
    }
  ]
}
FAIL-NEW: 1     FAIL-INPROG: 0
"""


def test_alerts_become_findings_with_mapped_severity() -> None:
    """Every alert becomes a Finding, and all four ZAP risk codes map correctly."""
    out = parsers.parse_zap(NOISY_REPORT, SESSION, "run-1")

    by_title = {f.title: f for f in out.findings}
    assert len(out.findings) == 4, f"expected 4 findings, got {len(out.findings)}"

    assert by_title["SQL Injection"].severity == "high", "riskcode 3 must map to high"
    assert by_title["Cross Site Scripting (Reflected)"].severity == "medium", "2 -> medium"
    assert by_title["Content Security Policy Header Not Set"].severity == "low", "1 -> low"
    assert by_title["Timestamp Disclosure"].severity == "info", "0 -> info"

    sqli = by_title["SQL Injection"]
    assert sqli.tool == "zap", f"tool must be 'zap', got {sqli.tool!r}"
    assert sqli.reference == "pluginid:40018", f"got {sqli.reference!r}"
    assert sqli.target == "http://lab.local/search", f"got {sqli.target!r}"
    assert "syntax error" in sqli.evidence, f"evidence lost: {sqli.evidence!r}"
    assert sqli.session_id == SESSION and sqli.source_run_id == "run-1"
    print("  4 alerts -> findings, all four risk codes mapped: PASS")


def test_instances_become_endpoints() -> None:
    """Each alert instance with an http(s) URI becomes an Endpoint carrying its param."""
    out = parsers.parse_zap(NOISY_REPORT, SESSION, "run-1")

    urls = {e.url for e in out.endpoints}
    assert "http://lab.local/search" in urls, f"missing the SQLi URL: {sorted(urls)}"
    assert "http://lab.local/x" in urls, f"missing the XSS URL: {sorted(urls)}"

    search = next(e for e in out.endpoints if e.url == "http://lab.local/search")
    assert search.method == "GET", f"got {search.method!r}"
    assert search.params == ["q"], f"param not carried: {search.params!r}"

    xss = next(e for e in out.endpoints if e.url == "http://lab.local/x")
    assert xss.method == "POST", f"method not carried: {xss.method!r}"

    blank = next(e for e in out.endpoints if e.url == "http://lab.local/")
    assert blank.params == [], f"an empty param must not become a param: {blank.params!r}"
    print("  instances -> endpoints with method and param: PASS")


def test_the_report_is_found_inside_progress_noise() -> None:
    """*** THE POINT OF THE CUSTOM EXTRACTOR. ***

    _json_objects() cannot do this: the whole document does not parse (progress lines), and no
    single line parses either (the report is pretty-printed). A positive control in the same
    test proves the assertion is live — a bare report with no noise must also work, so a
    parser that has broken into always-empty cannot pass this.
    """
    noisy = parsers.parse_zap(NOISY_REPORT, SESSION, None)
    assert noisy.findings, "the report was not found inside the progress noise"

    # positive control: the same report with the noise stripped
    bare = NOISY_REPORT[NOISY_REPORT.index("{"): NOISY_REPORT.rindex("}") + 1]
    clean = parsers.parse_zap(bare, SESSION, None)
    assert len(clean.findings) == len(noisy.findings), (
        f"noise changed the result: {len(noisy.findings)} vs {len(clean.findings)} clean"
    )

    # and _json_objects genuinely cannot: this is why the custom extractor exists
    assert not list(parsers._json_objects(NOISY_REPORT)), (
        "_json_objects now handles this input — re-check whether the custom extractor is "
        "still needed, and do not silently keep two code paths"
    )
    print("  the report is extracted from surrounding progress output: PASS")


def test_garbage_never_raises_and_yields_nothing() -> None:
    """A parser must never break a completed run."""
    for junk in ("", "   ", "not json at all", "{", "{}", '{"site": "not-a-list"}',
                 '{"nope": 1}', "[1,2,3]", '{"site": [{"alerts": "no"}]}'):
        out = parsers.parse_zap(junk, SESSION, None)
        assert out.is_empty(), f"{junk!r} produced records: {out.counts()}"
    print("  9 malformed inputs yield empty and never raise: PASS")


def test_the_stdout_registry_is_keyed_the_way_program_name_spells_it() -> None:
    """THE BUILD #9 DEFECT CLASS. program_name() strips .exe but NOT .py, so the keys must
    carry the .py suffix. Keying them 'zap-full-scan' would silently ingest nothing — which is
    exactly how a live DCSync dumped krbtgt and ingested none of it."""
    from state.ingest import program_name

    for spelling in ("zap-baseline.py", "/usr/share/zaproxy/zap-baseline.py", "ZAP-BASELINE.PY"):
        key = program_name(spelling)
        assert key in parsers.STDOUT_PARSERS, (
            f"program_name({spelling!r}) -> {key!r}, which is NOT a STDOUT_PARSERS key. "
            f"Keys present: {sorted(parsers.STDOUT_PARSERS)}"
        )
        assert parsers.STDOUT_PARSERS[key] is parsers.parse_zap

    assert program_name("zap-full-scan.py") in parsers.STDOUT_PARSERS
    # positive control: the normaliser really does keep .py (if it ever starts stripping it,
    # this test must fail rather than quietly pass on a key that no longer matches)
    assert program_name("zap-full-scan.py") == "zap-full-scan.py", (
        f"program_name no longer preserves .py (got {program_name('zap-full-scan.py')!r}) — "
        "the registry keys above are now wrong"
    )
    print("  STDOUT_PARSERS keys match program_name's spelling: PASS")


def test_the_file_registry_does_not_claim_every_json_file() -> None:
    """FILE_PARSERS is registered on '-zap.json', not '.json'. A bare '.json' registration
    would claim every JSON loot file any tool ever writes."""
    assert "-zap.json" in parsers.FILE_PARSERS, "the ZAP suffix is not registered"
    assert ".json" not in parsers.FILE_PARSERS, (
        "'.json' is registered — this claims every JSON loot file in the tree"
    )

    claimed = parsers.parse_file("report-zap.json", NOISY_REPORT, SESSION, None)
    assert claimed.findings, "a -zap.json loot file was not parsed"

    not_claimed = parsers.parse_file("subfinder-output.json", NOISY_REPORT, SESSION, None)
    assert not_claimed.is_empty(), (
        "a non-ZAP .json loot file was claimed by the ZAP parser: "
        f"{not_claimed.counts()}"
    )
    print("  -zap.json is claimed, a plain .json file is not: PASS")


if __name__ == "__main__":
    test_alerts_become_findings_with_mapped_severity()
    test_instances_become_endpoints()
    test_the_report_is_found_inside_progress_noise()
    test_garbage_never_raises_and_yields_nothing()
    test_the_stdout_registry_is_keyed_the_way_program_name_spells_it()
    test_the_file_registry_does_not_claim_every_json_file()
    print("ALL ZAP parser tests pass")
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd backend && .venv/Scripts/python.exe test_zap.py
```

Expected: `AttributeError: module 'state.parsers' has no attribute 'parse_zap'`

- [ ] **Step 3: Implement the parser**

In `backend/state/parsers.py`, insert after `parse_nuclei` (ends ~line 253) and before the `FILE_PARSERS` block:

```python
# --------------------------------------------------------------------------- #
# ZAP — the traditional-JSON report
# --------------------------------------------------------------------------- #
#: ZAP risk codes. Emitted as STRINGS in the JSON report. ZAP has no "critical".
_ZAP_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def _zap_report(text: str) -> dict[str, Any] | None:
    """Dig the ZAP report object out of a stream that also carries progress lines.

    `_json_objects` cannot do this and is deliberately not extended to: the scan scripts print
    progress before the report, so the whole document does not parse, and the report is
    pretty-printed across many lines, so no single line parses either. Both of its branches
    miss. Scan for a '{' that begins a decodable object carrying a "site" key.
    """
    blob = (text or "").strip()
    if not blob:
        return None
    decoder = json.JSONDecoder()
    idx = blob.find("{")
    while idx != -1:
        try:
            obj, _end = decoder.raw_decode(blob, idx)
        except ValueError:
            idx = blob.find("{", idx + 1)
            continue
        if isinstance(obj, dict) and "site" in obj:
            return obj
        idx = blob.find("{", idx + 1)
    return None


def parse_zap(text: str, session_id: str, run_id: str | None = None) -> Parsed:
    """ZAP alerts -> Findings; alert instances -> Endpoints."""
    out = Parsed()
    report = _zap_report(text)
    if report is None:
        return out
    sites = report.get("site")
    if not isinstance(sites, list):
        return out
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            name = str(alert.get("name") or alert.get("alert") or "").strip()
            if not name:
                continue
            instances = [i for i in (alert.get("instances") or []) if isinstance(i, dict)]
            first = instances[0] if instances else {}
            plugin = str(alert.get("pluginid") or "").strip()
            out.findings.append(
                Finding(
                    session_id=session_id, title=name,
                    severity=_ZAP_RISK.get(str(alert.get("riskcode") or "").strip(), "info"),
                    target=str(first.get("uri") or site.get("@name") or ""),
                    tool="zap",
                    reference=f"pluginid:{plugin}" if plugin else "",
                    evidence=str(first.get("evidence") or first.get("attack") or "")[:2000],
                    source_run_id=run_id,
                )
            )
            for inst in instances:
                uri = str(inst.get("uri") or "")
                if not uri.startswith("http"):
                    continue
                param = str(inst.get("param") or "").strip()
                out.endpoints.append(
                    Endpoint(
                        session_id=session_id, url=uri,
                        method=str(inst.get("method") or "GET").upper(),
                        params=[param] if param else [],
                        source_run_id=run_id,
                    )
                )
    return out
```

- [ ] **Step 4: Wire the registries**

In `backend/state/parsers.py`, change the `FILE_PARSERS` block (line ~314) to:

```python
FILE_PARSERS = {
    ".xml": parse_nmap_xml,
    # NOT ".json" — that would claim every JSON loot file any tool ever writes. ZAP's report
    # filename is set by the catalog templates (Task 2), which always end it in -zap.json.
    "-zap.json": parse_zap,
}
```

And add to `STDOUT_PARSERS` (line ~319), inside the existing dict:

```python
    # ingest.program_name() strips .exe but NOT .py, so these keys keep the suffix. Confirmed
    # against the built image in Task 4 — Kali's spelling wins over upstream's if they differ.
    "zap-baseline.py": parse_zap,
    "zap-full-scan.py": parse_zap,
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cd backend && .venv/Scripts/python.exe test_zap.py
```

Expected: `ALL ZAP parser tests pass`

- [ ] **Step 6: Confirm no existing parser regressed**

```bash
cd backend && .venv/Scripts/python.exe test_state.py
```

Expected: PASS. `_json_objects` was not touched, so this must be green.

- [ ] **Step 7: Commit**

```bash
git add backend/state/parsers.py backend/test_zap.py
git commit -m "build #14: ZAP report parser + registry wiring

parse_zap maps ZAP alerts onto the existing Finding/Endpoint records — no
schema change. It does its own JSON extraction because _json_objects cannot
reach this input: the scan scripts print progress before a pretty-printed
report, so neither the whole-document branch nor the line-delimited branch
matches. A test asserts _json_objects still cannot, so the two paths do not
silently become redundant.

Registry keys carry the .py suffix because ingest.program_name() strips .exe
but not .py, unlike allowlist._tool_name() which strips both. Getting that
backwards is the build #9 ingest gap: keys that never match, zero findings,
green suite. A test pins the spelling against program_name itself.

FILE_PARSERS is registered on -zap.json rather than .json so it does not
claim every JSON loot file in the tree."
```

---

### Task 2: Catalog entry + danger classification (ATOMIC)

**These must land in one commit.** `test_arsenal_safety.py::_catalog_invocations()` iterates every template's `argv[0]` and fails if any invocation has no danger verdict. Adding the catalog entry without the buckets breaks the suite; adding the buckets without the entry is dead code.

**Files:**
- Modify: `backend/arsenal/tools.json` (add one tool entry — CRLF, patch in place)
- Modify: `backend/cockpit/allowlist.py` (add `_ACTIVE_WEB_SCANNERS` after `_PERSISTENCE_TOOLS` at line ~196; add the check inside `dangerous_command_heuristic`)
- Modify: `backend/test_arsenal_safety.py` (add both invocations to their buckets)
- Create: `backend/test_zap_safety.py`

**Interfaces:**
- Consumes: `dangerous_command_heuristic(command: str, args: list[str]) -> list[str]` from `cockpit/allowlist.py`; `loader.load().tools` from `arsenal/loader.py`.
- Produces: catalog invocations `zap-baseline.py` (passive) and `zap-full-scan.py` (active). Task 4 confirms these names against the built image.

> **DECISION RESOLVED (2026-08-03, Zaid): ship as specced.** `zap-full-scan.py` demands the
> red-confirm; `sqlmap`, `nikto`, `dalfox` and `nuclei` stay in `_MUST_NOT_FIRE` untouched. ZAP
> is deliberately stricter than the rest of its family — see the decision note at the end of
> this plan before changing it.

- [ ] **Step 1: Write the failing test**

Create `backend/test_zap_safety.py`:

```python
"""ZAP gating locks.  Run:  python test_zap_safety.py

Two invariants:
  1. an ACTIVE ZAP scan demands the red-confirm; a PASSIVE one does not
  2. the danger verdict is driven by the name the executor actually classifies
"""

from __future__ import annotations

from arsenal import loader
from cockpit import allowlist

ACTIVE = "zap-full-scan.py"
PASSIVE = "zap-baseline.py"


def _fires(command: str, args: list[str] | None = None) -> bool:
    return bool(allowlist.dangerous_command_heuristic(command, args or []))


def test_active_fires_passive_does_not_with_a_live_control() -> None:
    """*** THE INVARIANT. *** An active scan sends live injection payloads at every discovered
    parameter; a baseline crawl observes. They must get different verdicts.

    The controls are in THIS test on purpose: a heuristic broken into always-True or
    always-False would otherwise satisfy half of it and look fine.
    """
    assert _fires(ACTIVE), f"{ACTIVE} does NOT demand the red-confirm"
    assert not _fires(PASSIVE), f"{PASSIVE} demands the red-confirm — a passive crawl must not"

    # positive control: a known-dangerous command still fires
    assert _fires("msfvenom"), "control failed — the heuristic fires on nothing"
    # negative control: a known-benign command still does not
    assert not _fires("nmap", ["-sV", "10.0.0.1"]), "control failed — the heuristic fires on all"
    print("  active fires, passive does not, both controls hold: PASS")


def test_the_verdict_survives_every_spelling_the_executor_may_see() -> None:
    """_tool_name() normalises path, case and the .py suffix. The verdict must not depend on
    which spelling a template or an operator used."""
    for spelling in (ACTIVE, f"/usr/share/zaproxy/{ACTIVE}", ACTIVE.upper(), "zap-full-scan"):
        assert _fires(spelling), f"{spelling!r} lost its danger verdict"
    for spelling in (PASSIVE, f"/usr/share/zaproxy/{PASSIVE}", "zap-baseline"):
        assert not _fires(spelling), f"{spelling!r} gained a danger verdict"
    print("  the verdict holds across path, case and .py spellings: PASS")


def test_a_wrapped_active_scan_still_fires() -> None:
    """D22: proxychains laundered a red-confirm once. The wrapper is not what runs."""
    assert _fires("proxychains", [ACTIVE, "-t", "http://x"]), (
        "proxychains launders the ZAP active-scan confirm — D22 returning"
    )
    print("  proxychains does not launder the active-scan confirm: PASS")


def test_the_catalog_really_contains_both_invocations() -> None:
    """Draw from the real source of truth: if the catalog stops shipping these templates the
    tests above are asserting about nothing, and this fails instead of quietly passing."""
    import shlex

    argv0s: set[str] = set()
    for tool in loader.load().tools:
        for tpl in tool.templates:
            try:
                parts = shlex.split(tpl.template, posix=True)
            except ValueError:
                parts = tpl.template.split()
            if parts:
                argv0s.add(parts[0].rsplit("/", 1)[-1])

    assert ACTIVE in argv0s, f"the catalog ships no {ACTIVE} template; found: {sorted(argv0s)}"
    assert PASSIVE in argv0s, f"the catalog ships no {PASSIVE} template"
    print(f"  the catalog ships both ZAP invocations ({len(argv0s)} argv[0]s total): PASS")


if __name__ == "__main__":
    test_active_fires_passive_does_not_with_a_live_control()
    test_the_verdict_survives_every_spelling_the_executor_may_see()
    test_a_wrapped_active_scan_still_fires()
    test_the_catalog_really_contains_both_invocations()
    print("ALL ZAP gating locks pass")
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd backend && .venv/Scripts/python.exe test_zap_safety.py
```

Expected: FAIL on `test_active_fires_passive_does_not_with_a_live_control` — `zap-full-scan.py does NOT demand the red-confirm`.

- [ ] **Step 3: Add the danger classification**

In `backend/cockpit/allowlist.py`, after `_PERSISTENCE_TOOLS` (line ~196), add:

```python
# ACTIVE web vulnerability scanners — these SEND live injection payloads (SQLi, XSS, command
# injection, path traversal) at every parameter they discover. A baseline/passive crawl of the
# same tool observes and is deliberately NOT here: gating both identically would make the
# confirm meaningless for the tool, the same failure the AD enumeration note describes.
#
# Keyed on _tool_name() output, so NO `.py` suffix — that normaliser strips it. The parser
# registry in state/parsers.py is keyed the other way (program_name keeps `.py`).
_ACTIVE_WEB_SCANNERS = frozenset({"zap-full-scan"})
```

Then inside `dangerous_command_heuristic`, immediately after the `_PERSISTENCE_TOOLS` check, add:

```python
    if cmd in _ACTIVE_WEB_SCANNERS:
        reasons.append(
            f"{cmd}: active web scan — sends live injection payloads at every discovered "
            "parameter"
        )
```

- [ ] **Step 4: Add the catalog entry**

In `backend/arsenal/tools.json`, add this object to the `tools` array, keeping the file's existing CRLF line endings and 2-space indentation. Place it adjacent to the other `"category": "web"` entries.

```json
    {
      "name": "zap",
      "category": "web",
      "purpose": "OWASP ZAP — spiders a web application and reports vulnerabilities. The baseline scan crawls and analyses traffic passively; the full scan additionally sends live injection payloads at every parameter it discovered.",
      "phases": ["enumeration", "exploitation"],
      "techniques": ["web crawling", "passive vulnerability analysis", "active injection scanning", "OWASP Top 10 coverage"],
      "docs": "https://www.zaproxy.org/docs/",
      "templates": [
        {
          "label": "Baseline scan (passive, report to stdout)",
          "template": "zap-baseline.py -t <target> -J /dev/stdout",
          "note": "Spider + passive rules only. Sends no attack traffic, so it needs approval but no red-confirm. Start here."
        },
        {
          "label": "Baseline scan with the AJAX spider (SPA targets)",
          "template": "zap-baseline.py -t <target> -j -J /dev/stdout",
          "note": "-j adds the AJAX spider. Slower, but the traditional spider finds almost nothing on a single-page app."
        },
        {
          "label": "Full active scan (report to stdout)",
          "template": "zap-full-scan.py -t <target> -J /dev/stdout",
          "note": "ACTIVE: sends real SQLi/XSS/command-injection payloads at every discovered parameter. Requires the red-confirm. Loud, and can take tens of minutes."
        },
        {
          "label": "Full active scan (report to the loot dir)",
          "template": "zap-full-scan.py -t <target> -J <output>-zap.json",
          "note": "Engagement form: the -zap.json suffix is what the loot ingester keys on. ACTIVE — same red-confirm as above."
        }
      ],
      "flags": [
        {"flag": "-t", "what": "target URL (include the scheme)"},
        {"flag": "-J", "what": "write the JSON report to this path"},
        {"flag": "-j", "what": "use the AJAX spider (needed for single-page apps)"},
        {"flag": "-m", "what": "minutes to spider before scanning"},
        {"flag": "-I", "what": "do not fail the run on warnings"}
      ]
    }
```

- [ ] **Step 5: Classify both invocations in the arsenal safety buckets**

In `backend/test_arsenal_safety.py`, add to `_MUST_FIRE` (line ~186), inside the frozenset:

```python
    # ACTIVE web scan — sends live injection payloads at every discovered parameter. The
    # PASSIVE sibling (zap-baseline.py) is in _MUST_NOT_FIRE; that split is the whole point.
    "zap-full-scan.py",
```

And to `_MUST_NOT_FIRE`, next to the other web-testing entries (line ~225):

```python
    "zap-baseline.py",
```

Both keep the `.py` suffix: `_catalog_invocations()` basenames but does not strip suffixes — the same reason `jwt_tool.py` and `testssl.sh` are spelled that way.

- [ ] **Step 6: Confirm there is no second derivation to drift**

Spec §6 item 2 requires "the string the gate classifies is the string that executes." For ZAP
this holds **by construction** and needs no new test: unlike `tunnels.py`, ZAP adds no second
derivation. The executor classifies `request.command` and runs `request.command` — one value,
already locked by `test_cockpit.py`. This is the concrete payoff of approach A, and it is worth
confirming rather than assuming:

```bash
cd backend && grep -n "dangerous_command_heuristic\|danger_reasons_for_mode" cockpit/executor.py | head
```

Expected: the danger check reads from the same `ExecRequest` the run uses. If a ZAP-specific
code path is ever added that builds its own argv, that path needs the `tunnels.py` treatment —
one shared derivation function behind both the gate and the action.

- [ ] **Step 7: Run all three affected suites**

```bash
cd backend && .venv/Scripts/python.exe test_zap_safety.py && .venv/Scripts/python.exe test_arsenal_safety.py && .venv/Scripts/python.exe test_arsenal.py
```

Expected: all three PASS. If `test_arsenal.py` fails to load the catalog, the JSON edit is malformed — check for a missing comma rather than reformatting the file.

- [ ] **Step 8: Commit**

```bash
git add backend/arsenal/tools.json backend/cockpit/allowlist.py backend/test_arsenal_safety.py backend/test_zap_safety.py
git commit -m "build #14: ZAP catalog entry + the active/passive gating split

Atomic on purpose: _catalog_invocations() fails the suite for any catalogued
argv[0] with no danger verdict, so the entry and its classification cannot
land separately.

zap-full-scan.py demands the red-confirm; zap-baseline.py does not. Gating
both identically would make the confirm meaningless for the tool — the same
argument the AD-enumeration note in _MUST_NOT_FIRE already makes.

_ACTIVE_WEB_SCANNERS is keyed WITHOUT .py because _tool_name() strips it,
while the parser registry is keyed WITH .py because program_name() does not.
The two normalisers genuinely differ; a test pins each side to its own."
```

---

### Task 3: Detection aliases

Small, self-contained, and closes a silent hole: `ALIASES` maps `zap` and `zaproxy`, but neither is the program name that will execute.

**Files:**
- Modify: `backend/detection/catalog.py:1257-1258` (the web block of `ALIASES`)
- Modify: `backend/test_zap.py` (add one test)

**Interfaces:**
- Consumes: `ALIASES: dict[str, str]` from `backend/detection/catalog.py`.
- Produces: nothing other tasks depend on.

- [ ] **Step 1: Write the failing test**

Append to `backend/test_zap.py`, before the `if __name__ == "__main__":` block:

```python
def test_detection_describes_the_names_that_actually_run() -> None:
    """ALIASES already maps 'zap'/'zaproxy', but runs are zap-baseline.py / zap-full-scan.py.
    Without these the detection panel goes silent on every ZAP run while looking healthy —
    a surface reporting nothing is indistinguishable from one with nothing to report."""
    from detection.catalog import ALIASES

    for name in ("zap-baseline.py", "zap-full-scan.py"):
        assert name in ALIASES, f"{name} is not in detection ALIASES — the panel will be blank"
        assert ALIASES[name] == "web_vuln_scan", f"{name} -> {ALIASES[name]!r}"

    # positive control: the pre-existing spellings are untouched
    assert ALIASES["zap"] == "web_vuln_scan" and ALIASES["zaproxy"] == "web_vuln_scan"
    print("  detection covers the program names that actually execute: PASS")
```

Add the call to the `__main__` block:

```python
    test_detection_describes_the_names_that_actually_run()
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd backend && .venv/Scripts/python.exe test_zap.py
```

Expected: FAIL — `zap-baseline.py is not in detection ALIASES`.

- [ ] **Step 3: Add the aliases**

In `backend/detection/catalog.py`, change line 1258 from:

```python
    "zaproxy": "web_vuln_scan", "wapiti": "web_vuln_scan", "joomscan": "web_vuln_scan",
```

to:

```python
    "zaproxy": "web_vuln_scan", "wapiti": "web_vuln_scan", "joomscan": "web_vuln_scan",
    # the names that ACTUALLY execute — "zap"/"zaproxy" above are neither
    "zap-baseline.py": "web_vuln_scan", "zap-full-scan.py": "web_vuln_scan",
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd backend && .venv/Scripts/python.exe test_zap.py && .venv/Scripts/python.exe test_detection.py
```

Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/detection/catalog.py backend/test_zap.py
git commit -m "build #14: detection aliases for the ZAP names that actually run

ALIASES mapped 'zap' and 'zaproxy'; neither is what executes. Without this
the detection panel describes nothing for every ZAP run while appearing
perfectly healthy — the silent-hole shape the gate audit was about."
```

---

### Task 4: Sandbox image layer + verify the installed names

The only task needing Docker. It also **verifies the assumption Tasks 1-3 were written against** — that Kali spells the scripts `zap-baseline.py` and `zap-full-scan.py`.

**Files:**
- Modify: `docker/Dockerfile.sandbox` (new layer after the web/recon layer, currently lines 56-65)
- Modify: `backend/state/parsers.py` and/or `backend/arsenal/tools.json` — ONLY if the verified names differ

**Interfaces:**
- Consumes: the catalog templates from Task 2, the registry keys from Task 1.
- Produces: a built `hackpit/kali-sandbox:m1` image containing ZAP.

- [ ] **Step 1: Resolve spec §7 — does the executor time out a long scan?**

A full active scan runs for tens of minutes; the executor is built for commands that finish.
Find out what it does before running one, rather than discovering it mid-engagement.

```bash
cd backend && grep -rn "timeout" cockpit/executor.py cockpit/jobs.py cockpit/runstore.py | head -20
```

Then act on what you find:

- **No timeout** — nothing to do. Note it in the Task 4 commit message.
- **A timeout longer than ~30 minutes** — nothing to do; note the value.
- **A timeout shorter than ~30 minutes** — a full scan will be killed mid-run. Do NOT raise the
  global timeout to accommodate one tool. Instead add `-m 2` (spider minutes) and a note to the
  full-scan catalog templates capping the scan to fit, and record the ceiling in the assessment
  so the limit is stated rather than hit. Raising a global timeout for one tool changes
  behaviour for every other tool that relies on it.

- [ ] **Step 2: Add the image layer**

In `docker/Dockerfile.sandbox`, after the web/recon layer (ends line 65), insert:

```dockerfile
# --- 3b. Web application scanner (ZAP) ---------------------------------------
# OWASP ZAP + a headless JRE. Its own layer because it is large and stable: an edit to the
# tool layers above must not force it to rebuild.
#
# ZAP writes state to $HOME/.ZAP and REFUSES TO START if that path is not writable. The image
# default user is `sandbox` (uid 1000), so the directory is created and chowned here rather
# than discovered at runtime as a scan that dies instantly.
#
# Add-ons are baked at build time on purpose: the lab sandbox joins an `internal: true` network
# and has NO egress, so it can never fetch one at runtime. Same reason nuclei-templates is baked.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        zaproxy default-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /home/sandbox/.ZAP \
    && chown -R sandbox:sandbox /home/sandbox/.ZAP \
    && zap.sh -version \
    && command -v zap-baseline.py \
    && command -v zap-full-scan.py

# The three checks above are the smoke test, and they are three because they can fail
# separately: the package can install while shipping the scan scripts under a different name
# or leaving them off PATH. A build that succeeds here is a build whose catalog templates and
# parser registry keys are known-correct. `command -v` is NOT a smoke test on its own (build
# #4's lesson) — `zap.sh -version` is the one that proves the JVM starts.
```

- [ ] **Step 3: Build the image**

```bash
docker compose -f docker/docker-compose.yml build kali-sandbox
```

Expected: SUCCESS. This is a large, slow build.

**If it fails at `command -v zap-baseline.py`:** the package does not ship the scripts on PATH. Find where they landed:

```bash
docker run --rm hackpit/kali-sandbox:m1 sh -c "find / -name 'zap-*scan*.py' -o -name 'zap-baseline*' 2>/dev/null"
```

Then either symlink them into `/usr/local/bin` in this layer, or fetch them as pinned files in layer 8 alongside ffuf/nuclei. **Whichever spelling ends up on PATH is the one the catalog templates and parser keys must use** — go back and correct Tasks 1 and 2 rather than assuming upstream's names.

- [ ] **Step 4: Verify the installed names match what the code expects**

```bash
docker run --rm hackpit/kali-sandbox:m1 sh -c "command -v zap-baseline.py zap-full-scan.py && zap-baseline.py --help 2>&1 | head -5"
```

Expected: both resolve to real paths.

- [ ] **Step 5: Reconcile if the names differ**

If either name differs from what Tasks 1-2 assumed, update **all three** places and re-run their tests:
- `STDOUT_PARSERS` keys in `backend/state/parsers.py`
- the `template` strings in `backend/arsenal/tools.json`
- the bucket entries in `backend/test_arsenal_safety.py` and the constants in `backend/test_zap_safety.py`

If they match, no change — record that they were checked in the commit message.

- [ ] **Step 6: Run a real passive scan against the lab target**

Bring the stack up, then:

```bash
docker compose -f docker/docker-compose.yml up -d
docker exec hackpit-kali-sandbox zap-baseline.py -t http://hackpit-lab-target:3000 -J /dev/stdout -m 1 > /tmp/zap-lab.json
```

Expected: a JSON report with a `site` array. Juice Shop is a SPA, so the traditional spider may find little — that is expected, not a failure. If it is empty, re-run with `-j` (AJAX spider).

- [ ] **Step 7: Prove the real output parses**

```bash
cd backend && .venv/Scripts/python.exe -c "
from state import parsers
text = open('/tmp/zap-lab.json', encoding='utf-8', errors='replace').read()
out = parsers.parse_zap(text, 's-live', 'run-live')
print('findings:', len(out.findings), 'endpoints:', len(out.endpoints))
for f in out.findings[:5]:
    print(' ', f.severity, '-', f.title)
assert out.findings, 'the REAL report parsed to nothing — the fixture and reality disagree'
"
```

Expected: a non-zero finding count. **This is the check the hermetic tests cannot make** — the fixture was written by us; this is ZAP's actual output.

- [ ] **Step 8: Commit**

```bash
git add docker/Dockerfile.sandbox
git commit -m "build #14: ZAP in the sandbox image, names verified against the build

Own layer (large + stable), add-ons baked because the lab sandbox has no
egress and can never fetch one at runtime. \$HOME/.ZAP is created and chowned
to the image's unprivileged sandbox user — ZAP refuses to start without it.

The smoke test is three checks, not one: the package can install while
shipping the scan scripts under a different name or off PATH, and that
mismatch is invisible until a live run ingests nothing. zap.sh -version
proves the JVM starts; command -v proves each script is callable under the
exact name the catalog templates and parser registry use.

Verified against the built image and a real baseline scan of the lab target,
whose actual report was parsed by parse_zap — the fixture in test_zap.py is
one we wrote, so only this step can catch the two disagreeing."
```

---

### Task 5: Wire into the suites, update the assessment

**Files:**
- Modify: `backend/run_safety_tests.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/ASSESSMENT-2026-07-26.md`
- Regenerate: `docs/ASSESSMENT-2026-07-26.html` + `.pdf` via `python docs/build-assessment.py`

**Interfaces:**
- Consumes: `backend/test_zap.py` and `backend/test_zap_safety.py` from Tasks 1-3.
- Produces: nothing other tasks depend on. This is the final task.

- [ ] **Step 1: Add both tests to the safety suite**

In `backend/run_safety_tests.sh`, add alongside the other `run_test` lines:

```sh
run_test test_zap.py         "ZAP report parser + registry keys + detection coverage"
run_test test_zap_safety.py  "ZAP active/passive gating split"
```

- [ ] **Step 2: Run the whole safety suite**

```bash
sh backend/run_safety_tests.sh
```

Expected: every test exits 0, including the two new files. If the count printed at the end did not grow by 2, the `run_test` lines are in the wrong place.

- [ ] **Step 3: Add the CI note**

`.github/workflows/ci.yml` documents which checks are hermetic and which need the live stack. Add to the same echo block that describes `test_redirector.py` (~line 95):

```yaml
            echo "- \`test_zap.py\` + \`test_zap_safety.py\` are fully hermetic — they parse a"
            echo "  committed fixture and iterate the real catalog, no Docker needed. What CI"
            echo "  CANNOT check is that the image installs the scan scripts under the names"
            echo "  the registry keys use; that is verified at image-build time (Task 4) and is"
            echo "  the build #9 ingest-gap shape."
```

- [ ] **Step 4: Update the assessment**

Add a subsection to `docs/ASSESSMENT-2026-07-26.md` recording:
- ZAP is the first active web vulnerability scanner in the arsenal; catalog is now 116 tools.
- It runs as a gated command, not a daemon — with the §3 reasoning in one sentence: an HTTP control channel would bypass `validate_request`, and reaching one inside the isolated lab sandbox would mean opening the path `assert_isolation_proven()` exists to deny.
- The active/passive split: `zap-full-scan.py` requires the red-confirm, `zap-baseline.py` does not.
- The two-normaliser trap, as a durable note: `_tool_name()` strips `.py`, `program_name()` does not.
- The proxy surface and the daemon are deferred to build #14 part 2.

- [ ] **Step 5: Regenerate and verify**

```bash
python docs/build-assessment.py
grep -c "zap-full-scan" docs/ASSESSMENT-2026-07-26.html
```

Expected: a non-zero count. **Verify against the HTML, never the PDF** — Edge subsets fonts to glyph IDs, so the PDF cannot be grepped.

- [ ] **Step 6: Commit**

```bash
git add backend/run_safety_tests.sh .github/workflows/ci.yml docs/ASSESSMENT-2026-07-26.md docs/ASSESSMENT-2026-07-26.html docs/ASSESSMENT-2026-07-26.pdf
git commit -m "build #14: ZAP tests in the suites + assessment

Assessment and its regenerated html/pdf land in this commit, not a later one.

Records the two-normaliser trap as a durable note: allowlist._tool_name()
strips .py, state.ingest.program_name() does not, so the danger sets and the
parser registry are keyed differently ON PURPOSE."
```

---

## Definition of done

- [ ] `sh backend/run_safety_tests.sh` passes, two files larger than before.
- [ ] The image builds and all three smoke-test checks pass.
- [ ] A real baseline scan of the lab target produces a report that `parse_zap` turns into findings.
- [ ] An active scan is refused without `dangerous_ack` and runs with it.
- [ ] The detection panel describes a ZAP run rather than showing nothing.
- [ ] `docs/ASSESSMENT-2026-07-26.md` updated and regenerated in the same commit, verified against the HTML.

## Decision — RESOLVED 2026-08-03 (Zaid): option 1, ship as specced

**`sqlmap`, `nikto`, `dalfox`, `nuclei` and `wpscan` are all in `_MUST_NOT_FIRE`.** They send attack traffic too — sqlmap is arguably more intrusive than a ZAP full scan. Putting `zap-full-scan.py` in `_MUST_FIRE` therefore makes ZAP the *only* active web scanner requiring the red-confirm.

Three options:

1. **Ship as specced** (this plan): ZAP active fires, the rest unchanged. Defensible — the heuristic is documented as "over-inclusive best-effort" and ZAP full-scan is the broadest of them, hitting every parameter with every payload class. Inconsistent, but errs safe.
2. **Reclassify the family**: move sqlmap/dalfox/nikto to `_MUST_FIRE` too. Consistent, but adds a confirm to tools used constantly — and `_MUST_NOT_FIRE`'s own AD note warns that a confirm firing on almost everything "stops meaning anything."
3. **Put ZAP active in `_MUST_NOT_FIRE`** with the family. Consistent, but drops a control on the loudest tool in the set and contradicts the approved spec.

**RESOLVED: option 1.** `zap-full-scan.py` goes in `_MUST_FIRE`; sqlmap/nikto/dalfox/nuclei are
left exactly as they are. Rationale accepted: the heuristic is documented as over-inclusive
best-effort, a ZAP full scan is the broadest tool in the set, and erring safe on the new tool
changes no existing behaviour. Task 2 implements this; no other task is affected.

The inconsistency is deliberate and recorded here so a future reader does not "fix" it by
quietly demoting ZAP. If the family is ever reclassified, that is its own decision.
