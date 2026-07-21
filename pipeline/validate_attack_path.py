"""End-to-end validation of the composed attack path across the FULL stack.

Runs the goals that exercise every piece landed this session and checks the
payoff programmatically (not by eyeball):

  1. Aikido (multi-tenant SaaS, bug bounty) — target profiler + grounded
     specialized steps + conditional branches.
  2. Aikido + pasted scope — out-of-scope drop (scoped=True).
  3. "SQL injection on a web app" / "XXE on a web app" — the eligibility fix:
     the previously-buried resource entries now surface as GROUNDED steps.
  4. "HTB box Principal" — writeup-first mode (origin=='writeup').

Prereqs:
  * backend running on :8000 with the current KB + vectors.
  * SET THE PROVIDER TO A FRONTIER MODEL FIRST (Claude Agent SDK) in the UI or via
    /llm-config — the profiler is reasoning-heavy and qwen3:8b under-performs it.
Run:  python pipeline/validate_attack_path.py
No third-party deps (urllib only).
"""

from __future__ import annotations

import json
import sys
import urllib.request

BASE = "http://localhost:8000"


def compose(goal: str, target_type: str | None = None, scope_text: str | None = None) -> dict:
    body = {"goal": goal, "target_type": target_type, "scope_text": scope_text}
    req = urllib.request.Request(
        f"{BASE}/attack-path",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())


def flat_steps(path: dict) -> list[dict]:
    return [s for ph in path.get("phases", []) for s in ph.get("steps", [])]


def stats(path: dict) -> dict:
    steps = flat_steps(path)
    grounded = [s for s in steps if s.get("entry_id") and not s.get("ai_suggested")]
    ai = [s for s in steps if s.get("ai_suggested")]
    branched = [s for s in steps if s.get("on_success") or s.get("on_blocked")]
    return {
        "total": len(steps),
        "grounded": len(grounded),
        "ai": len(ai),
        "branched": len(branched),
        "grounded_ids": [s["entry_id"] for s in grounded],
    }


RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def main() -> None:
    # ---- 1 & 2: Aikido (the real-SaaS payoff) --------------------------------
    print("\n== Aikido (multi-tenant SaaS, bug bounty) ==")
    p = compose(
        "Bug bounty on Aikido Security — multi-tenant AppSec SaaS at app.aikido.dev "
        "with GitHub-app integrations, webhooks and OAuth",
        target_type="bugbounty",
    )
    prof = p.get("profile", {})
    st = stats(p)
    print(f"  provider={p.get('provider')} model={p.get('model_used')} origin={p.get('origin')}")
    print(f"  target_class={prof.get('target_class')!r}")
    print(f"  priority_bug_classes={prof.get('priority_bug_classes')}")
    print(f"  steps: total={st['total']} grounded={st['grounded']} ai_suggested={st['ai']} branched={st['branched']}")
    check("Aikido: profiler identified a target class", bool(prof.get("target_class")))
    check("Aikido: profiler produced priority bug classes", len(prof.get("priority_bug_classes", [])) >= 2)
    check("Aikido: majority of steps are GROUNDED (not AI-fill)", st["grounded"] >= max(1, st["ai"]),
          f"{st['grounded']} grounded vs {st['ai']} ai")
    check("Aikido: at least one conditional branch present", st["branched"] >= 1,
          f"{st['branched']} branched steps")

    print("\n== Aikido + pasted scope (out-of-scope drop) ==")
    ps = compose(
        "Bug bounty on Aikido Security multi-tenant SaaS at app.aikido.dev",
        target_type="bugbounty",
        scope_text="In scope: app.aikido.dev. OUT OF SCOPE: billing.aikido.dev, "
        "/admin, /internal-tools, any accounts.google.com endpoint.",
    )
    oos_hosts = ["billing.aikido.dev", "/admin", "/internal-tools", "accounts.google.com"]
    cmds_blob = " ".join(
        c.get("cmd", "") for s in flat_steps(ps) for c in s.get("commands", [])
    ).lower()
    leaked = [h for h in oos_hosts if h.lower() in cmds_blob]
    check("Aikido+scope: scoped flag set", bool(ps.get("scoped")))
    check("Aikido+scope: no out-of-scope host/path leaked into commands", not leaked,
          f"leaked={leaked}" if leaked else "clean")

    # ---- 3: eligibility fix end-to-end --------------------------------------
    print("\n== Eligibility fix: buried SQLi/XSS/XXE now grounded ==")
    for goal, needle in [
        ("SQL injection on a web application", "sql"),
        ("XXE / XML external entity on a web application", "xml"),
    ]:
        pg = compose(goal, target_type="bugbounty")
        s = stats(pg)
        hit = any(needle in gid.lower() for gid in s["grounded_ids"])
        check(f"'{goal[:22]}…': a grounded step cites a '{needle}' KB entry", hit,
              f"grounded_ids sample={s['grounded_ids'][:4]}")

    # ---- 4: writeup-first mode ----------------------------------------------
    print("\n== Writeup-first: HTB box Principal ==")
    pw = compose("I'm attacking the HTB box Principal, give me the path")
    bw = pw.get("box_writeup") or {}
    check("Principal: origin == 'writeup'", pw.get("origin") == "writeup",
          f"origin={pw.get('origin')}")
    check("Principal: box_writeup links htb-box-principal", bw.get("id") == "htb-box-principal",
          f"box_writeup={bw.get('id')}")
    check("Principal: path has phases with steps", bool(flat_steps(pw)))

    # ---- summary ------------------------------------------------------------
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n{'='*54}\nRESULT: {passed}/{len(RESULTS)} checks passed")
    fails = [n for n, ok, _ in RESULTS if not ok]
    if fails:
        print("FAILED:", "; ".join(fails))
        sys.exit(1)
    print("ALL CHECKS PASSED — the full stack composes real-target paths.")


if __name__ == "__main__":
    main()
