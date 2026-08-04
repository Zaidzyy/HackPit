#!/usr/bin/env python3
"""Build #17 item 1 — re-enter the engagement with accurate authorization text.

NOT a feature and NOT a gate: a DATA FIX, and it must happen before item 4.

`eng-69ec01d0fe74` carries "...PASSIVE RECON ONLY this session (operator asleep); no active
scanning per rules of engagement." That was written for an unattended session and is no
longer true. Zaid has decided NOT to make that field enforceable — approve-each is the bound —
but running an active scan under a record that forbids it leaves an audit trail contradicting
the action.

WHY THIS EXITS THE OLD RECORD RATHER THAN JUST ENTERING A NEW ONE. The plan says "one call",
and `enter()` mints a fresh id rather than amending. Leaving the old record active would mean
GET /cockpit/engagement still returns the forbidding string alongside the corrected one —
which is the exact condition this fixes. So: exit, then enter. Same target, same scope.

Run from the repo root with the backend's venv python. Self-verifying: prints VERDICT and
exits non-zero on failure.
"""
import sys

sys.path.insert(0, "backend")

from cockpit import engagement  # noqa: E402

OLD = "eng-69ec01d0fe74"
TARGET = "www.crateandbarrel.me"
SCOPE = (
    "www.crateandbarrel.me, api-prod.thatconceptstore.com, thatconceptstore.com, "
    "www.cb2.ae, www.allsaints.me, www.lululemon.me, lapi.yellowblocks.me, "
    "www.shiseido.me, lego.me, psychobunny.me, fashion4less.me"
)
AUTH = (
    "Bugcrowd - Majid Al Futtaim Lifestyle, RetailSafe safe harbor, ongoing since 2019. "
    "Operator PRESENT and approving every command. ACTIVE testing is authorized this "
    "session, deliberately narrowed by the operator to a single READ-ONLY catalogue/search "
    "endpoint with recurse=false; no cart, checkout, account or newsletter path. Supersedes "
    "the passive-only text entered 2026-08-03 for an unattended session."
)

before = [e.engagement_id for e in engagement.list_active()]
print("ACTIVE_BEFORE=" + ",".join(before) if before else "ACTIVE_BEFORE=<none>")

if OLD in before:
    print(f"EXITED_OLD={engagement.exit_engagement(OLD)}")
else:
    print(f"NOTE: {OLD} is not active — exiting whatever is, so exactly one record remains")
    for e in before:
        engagement.exit_engagement(e)

rec = engagement.enter(TARGET, AUTH, scope_spec=SCOPE)
print(f"NEW_ID={rec.engagement_id}")
print(f"NEW_TARGET={rec.target}")
print(f"SCOPE_INCLUDE_N={len(rec.scope_include)}")

after = engagement.list_active()
print("ACTIVE_AFTER=" + ",".join(e.engagement_id for e in after))

ok = True
if len(after) != 1 or after[0].engagement_id != rec.engagement_id:
    print("FAIL: expected exactly one active engagement, the new one")
    ok = False
elif "PASSIVE RECON ONLY" in after[0].authorization.upper():
    print("FAIL: the stale passive-only text is still active")
    ok = False
elif sorted(after[0].scope_include) != sorted(
    [s.strip() for s in SCOPE.split(",") if s.strip()]
):
    print("FAIL: scope changed — it must be the SAME scope, only the prose differs")
    ok = False

print("VERDICT=" + ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
