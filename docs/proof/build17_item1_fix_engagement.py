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

*** THE PROPERTY IS PER-TARGET, NOT GLOBAL, AND THE FIRST VERSION OF THIS SCRIPT GOT THAT
WRONG. *** It asserted "exactly one active engagement" — written against a truncated read of
GET /cockpit/engagement that showed one record when there were 21. The other twenty are old
lab engagements against RFC1918 addresses, left active because engagement expiry (D4) was
reviewed and DECLINED; they are pre-existing state, not this plan's business, and exiting
them would be a destructive tidy-up nobody asked for. What actually matters is narrower and
checkable: **no ACTIVE engagement naming this target may forbid active scanning.**

IDEMPOTENT. Re-running must not mint a second corrected record — it checks for the sentinel
first and passes without writing.

Run from the repo root with the backend's venv python. Self-verifying: prints VERDICT and
exits non-zero on failure.
"""
import sys

sys.path.insert(0, "backend")

from cockpit import engagement  # noqa: E402

OLD = "eng-69ec01d0fe74"
# Identifies a record THIS script wrote. Keyed on the supersedes clause rather than the whole
# string so a later reword of the prose does not silently make the script re-enter.
MARKER = "Supersedes the passive-only text entered 2026-08-03"
FORBIDS = "PASSIVE RECON ONLY"
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

def for_target():
    return [e for e in engagement.list_active() if e.target == TARGET]


before = for_target()
print(f"ACTIVE_TOTAL={len(engagement.list_active())}  ACTIVE_FOR_TARGET={len(before)}")
for e in before:
    print(f"  {e.engagement_id} forbids_active={FORBIDS in e.authorization.upper()}")

corrected = [e for e in before if MARKER in e.authorization]
stale = [e for e in before if MARKER not in e.authorization]

if corrected and not stale:
    rec = corrected[0]
    print(f"ALREADY_CORRECT={rec.engagement_id} (idempotent — nothing written)")
else:
    for e in stale:
        print(f"EXITED={e.engagement_id} exit_ok={engagement.exit_engagement(e.engagement_id)}")
    if OLD in [e.engagement_id for e in stale]:
        print(f"NOTE: that included {OLD}, the record named in the plan")
    rec = corrected[0] if corrected else engagement.enter(TARGET, AUTH, scope_spec=SCOPE)
    print(f"ENGAGEMENT={rec.engagement_id}")

print(f"TARGET={rec.target}")
print(f"SCOPE_INCLUDE_N={len(rec.scope_include)}")

# --- the property, re-read from the store rather than from what we just returned -----------
after = for_target()
print("ACTIVE_FOR_TARGET_AFTER=" + ",".join(e.engagement_id for e in after))

ok = True
if not any(e.engagement_id == rec.engagement_id for e in after):
    print("FAIL: the corrected record is not active")
    ok = False
forbidding = [e.engagement_id for e in after if FORBIDS in e.authorization.upper()]
if forbidding:
    print(f"FAIL: these ACTIVE records still forbid active scanning on {TARGET}: {forbidding}")
    ok = False
if sorted(rec.scope_include) != sorted(
    [s.strip() for s in SCOPE.split(",") if s.strip()]
):
    print("FAIL: scope changed — it must be the SAME scope, only the prose differs")
    ok = False

print("VERDICT=" + ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
