"""SAFETY invariants for operator identity (backend/operator_identity.py).

This repo is PUBLIC — the first line of .gitignore says so ("ship CODE ONLY").
Operator identity is the one piece of genuinely personal data HackPit stores: a
real name, an email address, and an OSCP student id. Two ways that leaks, and
both are guarded here:

  1. COMMITTED TO A PUBLIC REPO. `operator.json` must be gitignored, asserted by
     asking git itself rather than by reading the ignore file and hoping the
     pattern means what it looks like it means. A name in public git history
     cannot be deleted afterwards.

  2. SERVED TO THE BROWSER. `public_profile()` returns name + handle; the OSID
     and email are report-only. A page has no use for either, and the split only
     holds if something checks it against the REAL configured values.

Also asserts the module is not named `operator.py`, which would shadow the STDLIB
`operator` module for the entire process (`backend/` is first on sys.path).
"""

from __future__ import annotations

import ast
import inspect
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import operator_identity  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


def _git_ignores(path: Path) -> bool:
    """Ask GIT, not the ignore file. A pattern that looks right and a pattern that
    works are different things, and only git's answer is the one that matters."""
    result = subprocess.run(
        ["git", "check-ignore", "-q", str(path)],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    return result.returncode == 0


def test_operator_config_is_gitignored() -> None:
    target = REPO_ROOT / "backend" / "operator.json"
    assert _git_ignores(target), (
        "backend/operator.json is NOT gitignored — a real name / OSID / email "
        "would be committed to a PUBLIC repo and could never be removed."
    )

    # POSITIVE CONTROL — the predicate must be able to answer "no". A checker that
    # returns True for everything would pass the assertion above and prove nothing.
    tracked = REPO_ROOT / "backend" / "operator_identity.py"
    assert not _git_ignores(tracked), (
        "the gitignore predicate says a TRACKED source file is ignored — it "
        "cannot distinguish, so the assertion above is worthless"
    )

    # The example file must stay committable, or nobody can see the shape.
    example = REPO_ROOT / "backend" / "operator.example.json"
    assert example.exists(), "operator.example.json is missing"
    assert not _git_ignores(example), "the example config must be committable"

    print("  operator.json ignored, operator_identity.py + example NOT ignored: PASS")


def test_module_does_not_shadow_stdlib_operator() -> None:
    """`backend/` is first on sys.path, so `backend/operator.py` would replace the
    stdlib `operator` module for every import in the process."""
    assert not (REPO_ROOT / "backend" / "operator.py").exists(), (
        "backend/operator.py shadows the STDLIB `operator` module — rename it"
    )
    import operator as stdlib_operator

    assert "site-packages" not in (stdlib_operator.__file__ or ""), stdlib_operator.__file__
    assert str(REPO_ROOT) not in (stdlib_operator.__file__ or ""), (
        f"`import operator` resolved into the repo: {stdlib_operator.__file__}"
    )
    print(f"  stdlib operator resolves outside the repo: PASS")


def test_browser_never_sees_osid_or_email() -> None:
    """The report-only fields must not reach /operator — checked against the REAL
    configured values, not a synthetic example the system never produces."""
    cfg = operator_identity.load()
    secret_fields = {k: cfg[k] for k in ("osid", "email") if cfg[k]}

    # NO `with`, deliberately — entering the context runs the app's LIFESPAN, which loads the
    # KB and hard-fails when `data/kb/entries.jsonl` is absent. That file is gitignored, so on a
    # clean checkout (CI, a fresh clone) this test died on app startup for a reason with nothing
    # to do with the identity leak it guards. `/operator` reads `operator_identity` directly and
    # needs no lifespan-loaded state, so skipping startup costs the check nothing and lets it run
    # everywhere. This is the same construction test_sliver_safety and test_obfuscation_safety
    # already use for their endpoint assertions.
    client = TestClient(main.app)
    response = client.get("/operator")
    assert response.status_code == 200, response.text
    body = response.json()
    payload = json.dumps(body)

    assert set(body) == {"name", "handle"}, f"/operator grew a field: {sorted(body)}"

    leaked = [k for k, v in secret_fields.items() if v in payload]
    assert not leaked, f"/operator leaked report-only field(s): {leaked}"

    # POSITIVE CONTROL — the same containment check must catch a value that IS
    # present. Without this, "no leaks" is indistinguishable from a broken check.
    assert cfg["name"] in payload or not cfg["name"], (
        "the configured name is absent from /operator — the check is looking at "
        "the wrong payload"
    )

    if secret_fields:
        print(
            f"  checked {len(secret_fields)} configured report-only field(s) "
            f"({', '.join(sorted(secret_fields))}) against /operator: PASS"
        )
    else:
        print(
            "  /operator exposes exactly {name, handle}: PASS\n"
            "    NOTE: osid and email are both unset, so the leak check had no "
            "values to look for (it arms itself once they are configured)."
        )


def test_endpoint_uses_the_masked_accessor() -> None:
    """Asserted on the AST, not a substring: an aliased import or a call opened
    inside a nested helper is invisible to a substring scan."""
    tree = ast.parse(inspect.getsource(main.operator_profile))
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute):
                called.add(fn.attr)
            elif isinstance(fn, ast.Name):
                called.add(fn.id)

    assert "load" not in called, "/operator calls the RAW load() — it carries osid + email"
    assert "public_profile" in called, "/operator must call the masked public_profile()"

    # POSITIVE CONTROL — the walk must flag a planted raw call.
    planted = ast.parse("def f():\n    return operator_identity.load()\n")
    planted_calls = {
        n.func.attr
        for n in ast.walk(planted)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert "load" in planted_calls, "the AST call-scan cannot fail"

    print(f"  scanned {len(called)} call sites in operator_profile: PASS")


def test_report_identity_is_spliced_not_prompted() -> None:
    """The model must never be asked to write a candidate name or an OSID — it
    would transcribe or invent one. The block is inserted by code, like evidence."""
    import report

    source = inspect.getsource(report.compose_report)
    assert "operator_identity.report_identity" in source, (
        "compose_report no longer splices the identity block"
    )

    # It must NOT be reachable from the prompt builder.
    prompt_source = inspect.getsource(report.build_prompt)
    assert "operator_identity" not in prompt_source, (
        "operator identity reached the PROMPT — the model must not be handed a "
        "real name or OSID to transcribe"
    )

    # Unconfigured yields "" so an empty config cannot produce empty labels.
    saved = operator_identity.load
    try:
        operator_identity.load = lambda: {"name": "", "handle": "", "osid": "", "email": ""}
        assert operator_identity.report_identity("oscp") == "", (
            "an unconfigured operator must render NO identity block"
        )
        # ...and a configured one must actually produce the OSID for an OSCP report,
        # or the invariant would pass by producing nothing in every case.
        operator_identity.load = lambda: {
            "name": "Test", "handle": "", "osid": "OS-12345", "email": "",
        }
        block = operator_identity.report_identity("oscp")
        assert "OS-12345" in block and "Test" in block, block
    finally:
        operator_identity.load = saved

    print("  identity spliced by code, absent from the prompt, empty when unset: PASS")


if __name__ == "__main__":
    print("== operator identity SAFETY invariants (public repo) ==")
    test_operator_config_is_gitignored()
    test_module_does_not_shadow_stdlib_operator()
    test_browser_never_sees_osid_or_email()
    test_endpoint_uses_the_masked_accessor()
    test_report_identity_is_spliced_not_prompted()
    print("all operator-identity safety tests passed")
    sys.exit(0)
