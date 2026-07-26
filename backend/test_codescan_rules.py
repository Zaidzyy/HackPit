"""Bundled Semgrep rules + ruleset picker (#6).

Locks the offline coverage expansion (Java/Go/PHP/Ruby/C#) and the ruleset resolver:
  - every bundled rule is well-formed (id / languages / severity / message / pattern(s));
  - combined coverage spans the 8 languages (Python/JS/TS + Java/Go/PHP/Ruby/C#);
  - resolve_ruleset maps picker keys -> paths and passes registry refs through verbatim;
  - when semgrep is installed, `semgrep --validate` accepts the whole bundled directory
    (real validation); when it isn't, that step is skipped (like the live-scan test).

Run:  python test_codescan_rules.py
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

from codescan import runner

RULES_DIR = Path(__file__).parent / "codescan" / "rules"


def test_every_bundled_rule_is_well_formed() -> None:
    langs: set[str] = set()
    total = 0
    for f in sorted(RULES_DIR.glob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert isinstance(doc, dict) and doc.get("rules"), f"{f.name}: no rules"
        for r in doc["rules"]:
            total += 1
            for key in ("id", "languages", "severity", "message"):
                assert r.get(key), f"{f.name}:{r.get('id')} missing {key}"
            assert any(str(k).startswith("pattern") or k == "match" for k in r), (
                f"{f.name}:{r['id']} has no pattern/match clause"
            )
            assert r["severity"] in ("ERROR", "WARNING", "INFO"), r["severity"]
            langs.update(r["languages"])
    print(f"  {total} bundled rules across {len(langs)} languages, all well-formed: PASS")
    return langs


def test_offline_coverage_spans_the_eight_languages() -> None:
    langs = test_every_bundled_rule_is_well_formed()
    for need in ("python", "javascript", "typescript", "java", "go", "php", "ruby", "csharp"):
        assert need in langs, f"offline bundle should now cover {need}"
    print("  offline bundle covers Python/JS/TS + Java/Go/PHP/Ruby/C#: PASS")


def test_ruleset_resolver() -> None:
    assert runner.resolve_ruleset(None) == str(runner.RULES_DIR), "default = the whole dir"
    assert runner.resolve_ruleset("bundled") == str(runner.RULES_DIR)
    assert runner.resolve_ruleset("languages").endswith("hackpit-languages.yaml")
    assert runner.resolve_ruleset("python-js-ts").endswith("hackpit-security.yaml")
    # an unknown value (a registry pack) is passed through verbatim
    assert runner.resolve_ruleset("p/security-audit") == "p/security-audit"
    keys = {r["key"] for r in runner.list_rulesets()}
    assert {"bundled", "python-js-ts", "languages"} <= keys
    print("  resolver: keys -> paths, registry refs pass through, picker lists offline sets: PASS")


def test_semgrep_validates_the_bundle_when_present() -> None:
    exe = shutil.which("semgrep")
    if not exe:
        print("  semgrep --validate: SKIPPED (semgrep not installed)")
        return
    proc = subprocess.run(
        [exe, "--validate", "--config", str(runner.RULES_DIR), "--quiet",
         "--metrics", "off", "--disable-version-check"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"semgrep rejected the bundled rules:\n{proc.stderr[:1500]}"
    print("  semgrep --validate accepts the whole bundled directory: PASS")


if __name__ == "__main__":
    test_every_bundled_rule_is_well_formed()
    test_offline_coverage_spans_the_eight_languages()
    test_ruleset_resolver()
    test_semgrep_validates_the_bundle_when_present()
    print("ALL codescan-rules tests pass")
