"""Task 1 — prove the substrate RUNS. Turn "110 tools" into a measured number.

`cockpit/reconcile.py` already answers *installed?* with one `command -v` sweep. This module
answers the harder, more honest question: does each catalogued tool ACTUALLY EXECUTE in the
real sandbox image, under its real security profile (`no-new-privileges` + `CapDrop: ALL`)?
"Installed" and "runs" are not the same claim — a setcap binary resolves on PATH and then dies
the moment the dropped capability is needed (nmap is the documented casualty of that class).

Three coverage tiers per tool:

    catalogued   it is in arsenal/tools.json (Linux platform)
    installed    a candidate binary name resolves on PATH inside the container
    runs         a trivial call (--version / --help / equivalent) actually EXECUTED —
                 the process ran and produced tool output, no exec/permission failure

WHY THIS SHAPE
* ONE `docker exec` per tool. The in-container shell resolves the binary from the tool's
  names+aliases, then tries version/help flags until one executes, and prints a structured
  block. Parsing happens here; the container only runs `command -v` and the trivial call.
* THE VERDICT IS MEASURED, NEVER ASSUMED. A tool that does not run is reported as
  not-running with the reason (not installed / wrong binary name / no-new-privileges landmine),
  never quietly counted as covered. That honesty is the entire point of the task.
* READ-ONLY-ish. The trivial call is `<bin> --version`; it reads a version string. This is not
  an execution surface for the loop — it has no path from the proposer, takes no target, and is
  a developer/CI measurement tool run by hand.

The static half — catalogued names vs. the Dockerfile's install lines — needs no stack and is
unit-tested in test_substrate.py; the live half writes docs/substrate-coverage.{json,md}.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTAINER = "hackpit-kali-sandbox"
DOCKERFILE = REPO_ROOT / "docker" / "Dockerfile.sandbox"
REPORT_JSON = REPO_ROOT / "docs" / "substrate-coverage.json"
REPORT_MD = REPO_ROOT / "docs" / "substrate-coverage.md"

# How long any single trivial call may take inside the container before we call it "ran but
# slow" (msfconsole loads for tens of seconds; a `timeout`-killed process still EXECUTED).
PROBE_TIMEOUT = 8
# The whole per-tool exec gets a little more headroom than one flag.
EXEC_TIMEOUT = 40.0

# Substrings in a trivial-call's output that mean the binary could NOT actually execute in this
# profile even though it resolved on PATH — the setcap / no-new-privileges landmine and friends.
# Deliberately conservative: a *version banner* that merely mentions "root" is not a failure, so
# these are phrased as the exec/permission errors those failures actually print.
EXEC_FAIL_MARKERS = (
    "operation not permitted",
    "permission denied",
    "no new privileges",
    "no-new-privileges",
    "exec format error",
    "cannot execute binary",
    "requires root privileges",
    "must be run as root",
    "requires elevated",
    "cap_net_raw",
    "you requested a scan type which requires root",
)


@dataclass
class ToolProbe:
    """The measured coverage for one catalogued tool."""

    name: str
    category: str
    platform: str = ""                 # "" = linux sandbox, "windows" = not applicable here
    candidates: list[str] = field(default_factory=list)  # names+aliases we tried to resolve
    installed: bool = False
    installed_as: str = ""             # the candidate that actually resolved
    runs: bool = False
    probe_flag: str = ""               # the flag that produced a run
    exit_code: int | None = None
    reason: str = ""                   # why it does NOT run (empty when it runs)
    output_head: str = ""              # first bytes of the trivial-call output (evidence)

    def tier(self) -> str:
        if self.platform == "windows":
            return "windows-only"
        if self.runs:
            return "runs"
        if self.installed:
            return "installed-no-run"
        return "not-installed"


# --------------------------------------------------------------------------- #
# classification — PURE, so it is unit-tested without Docker
# --------------------------------------------------------------------------- #
def classify(
    *,
    name: str,
    resolved: str,
    flag: str,
    exit_code: int | None,
    output: str,
) -> tuple[bool, str]:
    """Did the trivial call actually RUN? Returns (runs, reason-when-not).

    Inputs are exactly what the container reports back, so the same function decides the verdict
    for the live probe and for the hermetic test's synthetic fixtures — there is no second,
    untested code path deciding "runs".
    """
    low = (output or "").lower()
    if not resolved:
        return False, "not installed (no candidate binary resolved on PATH)"
    if exit_code is None:
        # The container never reached a trivial call — resolved but nothing executed.
        return False, "resolved on PATH but no trivial call executed"
    hit = next((m for m in EXEC_FAIL_MARKERS if m in low), "")
    if hit:
        return False, f"no-new-privileges / setcap landmine (output: '{hit}')"
    # A trivial call executed and did not print an exec/permission failure — the binary runs in
    # this profile. Exit code is intentionally NOT part of the verdict: a tool that rejects
    # `--version` with usage text and exit 1 still EXECUTED, which is what "runs" means here.
    return True, ""


# --------------------------------------------------------------------------- #
# the in-container probe — ONE exec per tool
# --------------------------------------------------------------------------- #
_PROBE_SCRIPT = r"""
bin=""
for cand in "$@"; do
  if command -v "$cand" >/dev/null 2>&1; then bin="$cand"; break; fi
done
if [ -z "$bin" ]; then echo "RESOLVED "; echo "DONE"; exit 0; fi
echo "RESOLVED $bin"
for f in --version -version -V version --help -h help; do
  out=$(timeout %d "$bin" $f 2>&1); rc=$?
  if [ $rc -ne 127 ]; then
    echo "FLAG $f"
    echo "RC $rc"
    echo "OUTPUT_START"
    printf '%%s' "$out" | head -c 500
    echo ""
    echo "OUTPUT_END"
    echo "DONE"
    exit 0
  fi
done
echo "FLAG "
echo "DONE"
exit 0
""" % PROBE_TIMEOUT


def _docker_probe(container: str, candidates: list[str]) -> tuple[str, str, int | None, str]:
    """Resolve + trivial-call one tool inside the container. Returns
    (resolved_binary, flag, exit_code, output_head)."""
    names = [c for c in candidates if c and not any(ch.isspace() for ch in c)]
    if not names:
        return "", "", None, ""
    proc = subprocess.run(
        ["docker", "exec", container, "sh", "-c", _PROBE_SCRIPT, "sh", *names],
        capture_output=True,
        timeout=EXEC_TIMEOUT,
    )
    return _parse_probe_output(proc.stdout.decode("utf-8", "replace"))


def _parse_probe_output(text: str) -> tuple[str, str, int | None, str]:
    resolved, flag, rc, out = "", "", None, ""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("RESOLVED "):
            resolved = ln[len("RESOLVED "):].strip()
        elif ln.startswith("FLAG "):
            flag = ln[len("FLAG "):].strip()
        elif ln.startswith("RC "):
            try:
                rc = int(ln[len("RC "):].strip())
            except ValueError:
                rc = None
        elif ln == "OUTPUT_START":
            body: list[str] = []
            i += 1
            while i < len(lines) and lines[i] != "OUTPUT_END":
                body.append(lines[i])
                i += 1
            out = "\n".join(body)[:500]
        i += 1
    return resolved, flag, rc, out


# --------------------------------------------------------------------------- #
# driving the whole catalog
# --------------------------------------------------------------------------- #
def _candidates(tool: Any) -> list[str]:
    """The binary names to try for a tool: its name + aliases. Packages that install under a
    different binary than the package name (testssl.sh, certipy, bloodyAD) are covered because
    those alternate names live in the catalog's ``aliases``."""
    return list(dict.fromkeys(tool.names()))


def probe_all(
    arsenal: Any,
    container: str = DEFAULT_CONTAINER,
    probe: Callable[[str, list[str]], tuple[str, str, int | None, str]] | None = None,
) -> list[ToolProbe]:
    """Measure every catalogued tool. ``probe`` is injectable so the test can drive a fake
    container; the default hits Docker."""
    run_probe = probe or (lambda c, cands: _docker_probe(c, cands))
    results: list[ToolProbe] = []
    for tool in arsenal.tools:
        cands = _candidates(tool)
        r = ToolProbe(
            name=tool.name,
            category=tool.category,
            platform=(getattr(tool, "platform", "") or "").lower(),
            candidates=cands,
        )
        if r.platform == "windows":
            # Cannot run on a Linux container by construction (D9) — not a substrate gap.
            r.reason = "windows-only tool — not applicable to the Linux sandbox"
            results.append(r)
            continue
        resolved, flag, rc, out = run_probe(container, cands)
        r.installed = bool(resolved)
        r.installed_as = resolved
        r.probe_flag = flag
        r.exit_code = rc
        r.output_head = out
        r.runs, r.reason = classify(
            name=tool.name, resolved=resolved, flag=flag, exit_code=rc, output=out
        )
        results.append(r)
    return results


def summarize(results: list[ToolProbe]) -> dict[str, Any]:
    linux = [r for r in results if r.platform != "windows"]
    runs = [r for r in linux if r.runs]
    installed_no_run = [r for r in linux if r.installed and not r.runs]
    not_installed = [r for r in linux if not r.installed]
    windows = [r for r in results if r.platform == "windows"]
    wrong_name = [r for r in runs if r.installed_as and r.installed_as != r.name]
    return {
        "catalogued": len(results),
        "linux_catalogued": len(linux),
        "runs": len(runs),
        "installed_no_run": len(installed_no_run),
        "not_installed": len(not_installed),
        "windows_only": len(windows),
        "resolved_under_alias": len(wrong_name),
        "run_rate": round(100.0 * len(runs) / len(linux), 1) if linux else 0.0,
    }


# --------------------------------------------------------------------------- #
# static half — catalogued names vs. the Dockerfile's install lines (NO stack)
# --------------------------------------------------------------------------- #
def static_coverage(arsenal: Any, dockerfile_text: str) -> dict[str, Any]:
    """Which catalogued Linux tools have any candidate binary named in the Dockerfile?

    A weak, honest signal — the Dockerfile installs packages, not binaries, and a metapackage
    (`kali-tools-web`) pulls in tools it never names. So this reports "named in the Dockerfile"
    vs "not named", and the live probe is what actually settles whether a tool RUNS. It is here
    because it needs no Docker and it flags the obviously-missing before a build.
    """
    hay = (dockerfile_text or "").lower()
    named, unnamed = [], []
    for tool in arsenal.tools:
        if (getattr(tool, "platform", "") or "").lower() == "windows":
            continue
        cands = [c.lower() for c in _candidates(tool)]
        if any(c in hay for c in cands):
            named.append(tool.name)
        else:
            unnamed.append(tool.name)
    return {
        "linux_catalogued": len(named) + len(unnamed),
        "named_in_dockerfile": sorted(named),
        "not_named_in_dockerfile": sorted(unnamed),
        "named_count": len(named),
    }


# --------------------------------------------------------------------------- #
# report writing + CLI
# --------------------------------------------------------------------------- #
def _tier_table(results: list[ToolProbe], tier: str) -> list[str]:
    rows = [r for r in results if r.tier() == tier]
    if not rows:
        return []
    lines = []
    for r in sorted(rows, key=lambda x: (x.category, x.name)):
        detail = r.installed_as or ""
        if r.installed_as and r.installed_as != r.name:
            detail = f"{r.installed_as} (aliased)"
        note = r.reason if r.reason else f"`{r.probe_flag}` exit {r.exit_code}"
        lines.append(f"| {r.name} | {r.category} | {detail} | {note} |")
    return lines


def write_report(results: list[ToolProbe], container: str) -> tuple[Path, Path]:
    summ = summarize(results)
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(
        json.dumps(
            {"container": container, "summary": summ, "tools": [asdict(r) for r in results]},
            indent=2,
        ),
        encoding="utf-8",
    )

    md: list[str] = []
    md.append("# Substrate coverage — do the catalogued tools actually run?\n")
    md.append(
        f"Measured against the live sandbox image (`{container}`, profile "
        "`no-new-privileges` + `CapDrop: ALL`) by invoking each catalogued tool with a trivial "
        "call (`--version` / `--help`). A tool that does not run is reported as not-running with "
        "the reason — never counted as covered.\n"
    )
    md.append("## Headline\n")
    md.append(
        f"- **{summ['runs']} of {summ['linux_catalogued']} catalogued Linux tools actually "
        f"execute** ({summ['run_rate']}%) in this image under its real profile.\n"
        f"- installed but does not run (landmine / caps): **{summ['installed_no_run']}**\n"
        f"- catalogued but not installed: **{summ['not_installed']}**\n"
        f"- resolved under an alias (package name != binary): **{summ['resolved_under_alias']}**\n"
        f"- Windows-only entries (not applicable to a Linux sandbox): **{summ['windows_only']}**\n"
    )
    for tier, title in (
        ("installed-no-run", "Installed but does NOT run (setcap / no-new-privileges landmine)"),
        ("not-installed", "Catalogued but NOT installed"),
    ):
        rows = _tier_table(results, tier)
        if rows:
            md.append(f"\n## {title}\n")
            md.append("| tool | category | resolved as | reason |")
            md.append("|---|---|---|---|")
            md.extend(rows)
    md.append("\n## Runs (executed under the live profile)\n")
    md.append("| tool | category | resolved as | probe |")
    md.append("|---|---|---|---|")
    md.extend(_tier_table(results, "runs"))
    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    return REPORT_JSON, REPORT_MD


def main(argv: list[str] | None = None) -> int:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from arsenal import loader  # noqa: E402

    args = argv if argv is not None else sys.argv[1:]
    container = DEFAULT_CONTAINER
    if "--container" in args:
        container = args[args.index("--container") + 1]

    arsenal = loader.load()
    if "--static" in args:
        cov = static_coverage(arsenal, DOCKERFILE.read_text(encoding="utf-8"))
        print(json.dumps(cov, indent=2))
        return 0

    print(f"probing {len(arsenal.tools)} catalogued tools in {container} …")
    results = probe_all(arsenal, container=container)
    summ = summarize(results)
    jp, mp = write_report(results, container)
    print(json.dumps(summ, indent=2))
    print(f"wrote {jp}\nwrote {mp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
