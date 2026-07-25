"""Verify the detection-footprint knowledge against its UPSTREAM public sources.

``backend/detection/`` carries a curated mapping — command family -> ATT&CK technique(s) ->
telemetry -> SigmaHQ rule(s) -> loudness. The technique ids, technique names, tactics and log
channels come from **MITRE ATT&CK Enterprise**; the rule UUIDs, titles and paths come from the
**SigmaHQ** open ruleset. This script re-checks every one of those facts against the live
sources so the mapping cannot silently drift (or, worse, contain something invented).

    python pipeline/detection_sources.py              # offline: internal consistency only
    python pipeline/detection_sources.py --verify     # + fetch ATT&CK + SigmaHQ and diff
    python pipeline/detection_sources.py --verify --cache-dir /tmp/ds   # reuse downloads

Exit code is non-zero when anything fails, so it can be wired into CI. The offline mode needs
no network and is what ``backend/test_detection.py`` runs.

Sources (both public, both used with attribution):
  * MITRE ATT&CK  — https://github.com/mitre-attack/attack-stix-data (MITRE ATT&CK Terms of Use)
  * SigmaHQ rules — https://github.com/SigmaHQ/sigma (Detection Rule License 1.1)
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND = REPO_ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from detection import attck, catalog  # noqa: E402

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
SIGMA_ZIP = "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master"
UA = {"User-Agent": "hackpit-detection-sources"}


# --------------------------------------------------------------------------- #
# offline: internal consistency
# --------------------------------------------------------------------------- #
def check_internal() -> list[str]:
    """Every id the catalog references must resolve. No network needed."""
    errs: list[str] = []

    for spec in catalog.SPECS.values():
        for tid in spec.techniques:
            if tid not in attck.TECHNIQUES:
                errs.append(f"spec {spec.key!r}: unknown ATT&CK technique {tid}")
        for key in spec.sigma:
            if key not in catalog.SIGMA:
                errs.append(f"spec {spec.key!r}: unknown Sigma key {key!r}")
        if spec.loudness not in catalog.LOUDNESS_SCALE:
            errs.append(f"spec {spec.key!r}: bad loudness {spec.loudness!r}")

    for sig in catalog.ARG_SIGNALS:
        for tid in sig.techniques:
            if tid not in attck.TECHNIQUES:
                errs.append(f"signal {sig.id!r}: unknown ATT&CK technique {tid}")
        for key in sig.sigma:
            if key not in catalog.SIGMA:
                errs.append(f"signal {sig.id!r}: unknown Sigma key {key!r}")
        try:
            re.compile(sig.pattern)
        except re.error as exc:
            errs.append(f"signal {sig.id!r}: bad pattern ({exc})")

    for tool, key in catalog.ALIASES.items():
        if key not in catalog.SPECS:
            errs.append(f"alias {tool!r} -> unknown spec {key!r}")
    for tool, subs in catalog.SUBCOMMAND_TOOLS.items():
        for sub, key in subs.items():
            if key not in catalog.SPECS:
                errs.append(f"subcommand {tool} {sub} -> unknown spec {key!r}")

    for tech in attck.TECHNIQUES.values():
        for tac in tech.tactics:
            if tac not in attck.TACTICS:
                errs.append(f"technique {tech.id}: unknown tactic {tac}")

    used = {t for s in catalog.SPECS.values() for t in s.techniques}
    used |= {t for s in catalog.ARG_SIGNALS for t in s.techniques}
    for tid in sorted(set(attck.TECHNIQUES) - used):
        errs.append(f"technique {tid} is in the ATT&CK table but no spec/signal uses it")

    used_sigma = {k for s in catalog.SPECS.values() for k in s.sigma}
    used_sigma |= {k for s in catalog.ARG_SIGNALS for k in s.sigma}
    for key in sorted(set(catalog.SIGMA) - used_sigma):
        errs.append(f"Sigma rule {key!r} is defined but no spec/signal cites it")

    return errs


# --------------------------------------------------------------------------- #
# online: diff against upstream
# --------------------------------------------------------------------------- #
def _fetch(url: str, cache: Path | None, name: str, timeout: int = 600) -> bytes:
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        blob = cache / name
        if blob.exists():
            print(f"  (cached) {blob}")
            return blob.read_bytes()
    print(f"  fetching {url}")
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        data = r.read()
    if cache is not None:
        (cache / name).write_bytes(data)
    return data


def check_attack(cache: Path | None) -> list[str]:
    """Every technique row must match live ATT&CK: name, tactics, log sources, non-revoked."""
    errs: list[str] = []
    bundle = json.loads(_fetch(ATTACK_URL, cache, "enterprise-attack.json"))
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}

    def eid(o):
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                return r.get("external_id")
        return None

    version = ""
    for o in objs:
        if o["type"] == "x-mitre-collection":
            version = str(o.get("x_mitre_version") or "")
    if version and version != attck.ATTACK_VERSION:
        errs.append(f"ATT&CK version drift: table says {attck.ATTACK_VERSION}, upstream is {version}")

    tactics_up = {}
    for o in objs:
        if o["type"] == "x-mitre-tactic":
            tactics_up[eid(o)] = (o["name"], o["x_mitre_shortname"])
    for tac, name in attck.TACTICS.items():
        up = tactics_up.get(tac)
        if up is None:
            errs.append(f"tactic {tac} not found upstream")
        elif up[0] != name:
            errs.append(f"tactic {tac}: table says {name!r}, upstream {up[0]!r}")

    techs = {}
    for o in objs:
        if o["type"] == "attack-pattern":
            techs[eid(o)] = o

    # technique -> the log-source strings its detection analytics name
    logs_for: dict[str, set[str]] = {}
    comps_for: dict[str, set[str]] = {}
    dets = [o for o in objs if o["type"] == "relationship" and o["relationship_type"] == "detects"]
    for rel in dets:
        strategy = by_id.get(rel["source_ref"])
        target = by_id.get(rel["target_ref"])
        if not strategy or not target or strategy["type"] != "x-mitre-detection-strategy":
            continue
        tid = eid(target)
        for aref in strategy.get("x_mitre_analytic_refs", []):
            a = by_id.get(aref)
            if not a:
                continue
            for ls in a.get("x_mitre_log_source_references", []):
                # Coarse-grained sources (plain "Network Traffic") carry no channel; upstream
                # serialises that as the literal string "None", so treat it as absent.
                chan = ls.get("channel") or ""
                if chan == "None":
                    chan = ""
                logs_for.setdefault(tid, set()).add(f"{ls.get('name') or ''} {chan}".strip())
                dc = by_id.get(ls.get("x_mitre_data_component_ref") or "")
                if dc:
                    comps_for.setdefault(tid, set()).add(dc.get("name"))

    for tech in attck.TECHNIQUES.values():
        up = techs.get(tech.id)
        if up is None:
            errs.append(f"{tech.id}: not found in ATT&CK Enterprise")
            continue
        if up.get("revoked") or up.get("x_mitre_deprecated"):
            errs.append(f"{tech.id}: revoked/deprecated upstream")
        # ATT&CK names sub-techniques with the leaf only; the table spells out "Parent: Leaf".
        leaf = tech.name.split(": ")[-1]
        if up["name"] != leaf:
            errs.append(f"{tech.id}: name {leaf!r} != upstream {up['name']!r}")
        up_tactics = {p["phase_name"] for p in up.get("kill_chain_phases", [])}
        short = {tactics_up[t][1] for t in tech.tactics if t in tactics_up}
        if short != up_tactics:
            errs.append(f"{tech.id}: tactics {sorted(short)} != upstream {sorted(up_tactics)}")
        up_comps = comps_for.get(tech.id, set())
        for c in tech.data_components:
            if up_comps and c not in up_comps:
                errs.append(f"{tech.id}: data component {c!r} not listed upstream")
        up_logs = logs_for.get(tech.id, set())
        for l in tech.log_sources:
            if up_logs and l not in up_logs:
                errs.append(f"{tech.id}: log source {l!r} not listed upstream")

    return errs


def check_sigma(cache: Path | None) -> list[str]:
    """Every cited Sigma rule must exist upstream at that path, with that UUID and title."""
    errs: list[str] = []
    blob = _fetch(SIGMA_ZIP, cache, "sigma-master.zip")
    rules: dict[str, dict] = {}
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for name in z.namelist():
            if "/rules" not in name or not name.endswith(".yml"):
                continue
            path = name.split("/", 1)[1]
            txt = z.read(name).decode("utf-8", "replace")

            def field(f):
                m = re.search(rf"^{f}:\s*(.+)$", txt, re.M)
                if not m:
                    return ""
                # strip a trailing inline comment, then quotes
                return re.sub(r"\s+#.*$", "", m.group(1)).strip().strip("'\"")

            rid = field("id")
            if rid:
                rules[path] = {"id": rid, "title": field("title"), "level": field("level")}

    by_uuid = {v["id"]: (p, v) for p, v in rules.items()}
    for key, rule in catalog.SIGMA.items():
        up = rules.get(rule.path)
        if up is None:
            moved = by_uuid.get(rule.id)
            if moved:
                errs.append(f"sigma {key!r}: path moved — {rule.path} -> {moved[0]}")
            else:
                errs.append(f"sigma {key!r}: {rule.path} not found in SigmaHQ")
            continue
        if up["id"] != rule.id:
            errs.append(f"sigma {key!r}: uuid {rule.id} != upstream {up['id']}")
        if up["title"] != rule.title:
            errs.append(f"sigma {key!r}: title {rule.title!r} != upstream {up['title']!r}")
        if up["level"] and up["level"] != rule.level:
            errs.append(f"sigma {key!r}: level {rule.level!r} != upstream {up['level']!r}")
    return errs


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verify", action="store_true",
                    help="also fetch ATT&CK + SigmaHQ and diff every cited fact")
    ap.add_argument("--cache-dir", default=None,
                    help="reuse downloads in this directory instead of re-fetching")
    args = ap.parse_args()
    cache = Path(args.cache_dir) if args.cache_dir else None

    print(f"detection knowledge: {len(catalog.SPECS)} specs, {len(catalog.ARG_SIGNALS)} arg signals, "
          f"{len(attck.TECHNIQUES)} ATT&CK techniques, {len(catalog.SIGMA)} Sigma rules")

    print("\n== internal consistency ==")
    errs = check_internal()
    print("  OK" if not errs else "\n".join("  FAIL " + e for e in errs))

    if args.verify:
        print(f"\n== MITRE ATT&CK Enterprise v{attck.ATTACK_VERSION} ==")
        a = check_attack(cache)
        print("  OK" if not a else "\n".join("  FAIL " + e for e in a))
        print("\n== SigmaHQ ruleset ==")
        s = check_sigma(cache)
        print("  OK" if not s else "\n".join("  FAIL " + e for e in s))
        errs += a + s

    print(f"\n{len(errs)} problem(s).")
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())
