"""SAFETY + HONESTY invariants for EGRESS-PROXY CONTROL.

Egress control routes a run's OUTBOUND traffic through a rotating, controllable source IP so a
single WAF ban does not strand a live bug-bounty engagement, and pins the program's identify
header so rotating IPs stay within the program's rules. It is an ARGUMENT REWRITE on an
already-gated request — the tool's own proxy flag (+ a header flag) — the same shape as the
recording proxy and pacing, and it must stay that shape:

  1. IT GRANTS NOTHING. An egressed command clears exactly the same gates as a direct one, and
     the REWRITTEN argv is what gets classified. The rewrite only ever ADDS tokens.
  2. ENGAGEMENT MODE ONLY. Lab and WinRM runs are byte-identical to before this existed.
  3. IT NEVER LIES ABOUT WHETHER IT WORKED. A tool with no proxy flag, an engagement with no
     pool, a lab/WinRM run, a run already on the recording proxy — each goes DIRECT from the
     sandbox IP, and each says so before any output. An operator who thinks every run rode the
     rotating pool while curl/python/unmapped tools went direct is exactly how the real IP
     leaks and gets banned.
  4. THE POOL IS A CREDENTIAL. A proxy URL may carry user:pass. It is held only by
     engagement.egress_config; it never reaches the EngagementRecord, a run note, or a report.
     The masked form is what any note/record shows.

Hermetic: sqlite only, no Docker, no network. Run:  python test_egress_safety.py
"""

from __future__ import annotations

import inspect
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import egress as EG  # noqa: E402
from cockpit import engagement as ENG  # noqa: E402
from cockpit import executor as E  # noqa: E402
from cockpit.models import ExecRequest  # noqa: E402

_LAB = "hackpit-lab-target"


class _StubPool:
    """Swap engagement.egress_config / egress_pool_size for a fixed pool, no DB. Restores on exit."""

    def __init__(self, pool: list[str], header: str = "") -> None:
        self._pool, self._header = pool, header

    def __enter__(self) -> "_StubPool":
        self._cfg, self._size = ENG.egress_config, ENG.egress_pool_size
        ENG.egress_config = lambda eid: (self._pool, self._header)  # type: ignore[assignment]
        ENG.egress_pool_size = lambda eid: len(self._pool)  # type: ignore[assignment]
        EG.reset("e1")
        return self

    def __exit__(self, *exc: object) -> None:
        ENG.egress_config, ENG.egress_pool_size = self._cfg, self._size
        EG.reset("e1")


# --------------------------------------------------------------------------- #
# 1. egress grants nothing — the rewrite only ADDS tokens, every gate still fires
# --------------------------------------------------------------------------- #
def test_egress_only_ever_prepends_and_still_faces_every_gate() -> None:
    # the argv rewrite never drops the operator's own tokens
    out, _ = E.apply_egress("curl", ["http://x"], "http://p:9")
    assert out[-1] == "http://x" and out[:2] == ["-x", "http://p:9"], out
    hdr, _ = E.apply_identify_header("curl", ["http://x"], "X-BB: me")
    assert hdr[-1] == "http://x" and hdr[:2] == ["-H", "X-BB: me"], hdr

    # validate_request reads the argv; an unapproved / off-target / dangerous request is refused
    # regardless of egress being asked for (the flag is added later, in iter_run, and can only
    # make the danger classifier fire MORE).
    unapproved = E.validate_request(
        ExecRequest(command="ffuf", args=["-u", f"http://{_LAB}/FUZZ"], approved=False, egress=True)
    )
    assert unapproved is not None and unapproved.gate in ("approval", "sandbox"), unapproved
    dangerous = E.validate_request(
        ExecRequest(command="sqlmap", args=["-u", f"http://{_LAB}/x", "--os-shell"],
                    approved=True, egress=True)
    )
    assert dangerous is not None and dangerous.gate == "danger", dangerous
    print("  egress only prepends, and a rewritten command still faces every gate: PASS")


def test_the_egress_rewrite_cancels_a_prevalidated_verdict() -> None:
    """Same hat as the proxy and pace rewrites: the argv the gates classified must be the argv
    that runs, so the rewrite precedes validation and cancels a stale prevalidated verdict."""
    src = inspect.getsource(E.iter_run)
    rewrite_at = src.find("apply_egress_to_request")
    validate_at = src.find("validate_request(request)")
    assert rewrite_at != -1 and validate_at != -1, "iter_run missing egress rewrite or validate"
    assert rewrite_at < validate_at, "iter_run validates BEFORE the egress rewrite"
    assert "if egress_note:" in src and "prevalidated = False" in src, (
        "the egress rewrite does not cancel a prevalidated verdict"
    )
    print("  the egress rewrite precedes validation and cancels a stale verdict: PASS")


# --------------------------------------------------------------------------- #
# 2. engagement mode only + opt-in
# --------------------------------------------------------------------------- #
def test_egress_is_engagement_mode_only_and_opt_in() -> None:
    args = ["-u", f"http://{_LAB}/FUZZ"]
    with _StubPool(["http://p1:9"]):
        # not asked for -> untouched
        plain = ExecRequest(command="ffuf", args=args, approved=True, engagement_id="e1")
        out, note = E.apply_egress_to_request(plain)
        assert out is plain and note == "", "a run that did not ask for egress was rewritten"

        # lab (no engagement_id) -> untouched
        lab = ExecRequest(command="ffuf", args=args, approved=True, egress=True)
        out_l, note_l = E.apply_egress_to_request(lab)
        assert out_l is lab and note_l == "", "a LAB run was egressed"

        # WinRM -> untouched (no argv to rewrite)
        win = ExecRequest(command="Get-Process", args=[], approved=True, egress=True,
                          windows_profile_id="w1")
        out_w, note_w = E.apply_egress_to_request(win)
        assert out_w is win and note_w == "", "a WinRM run was rewritten"

        # recording proxy already in play -> egress skipped (no double proxy flag)
        cap = ExecRequest(command="ffuf", args=args, approved=True, egress=True,
                          engagement_id="e1", proxy=True)
        out_c, note_c = E.apply_egress_to_request(cap)
        assert out_c is cap and note_c == "", "egress stacked a second proxy flag over capture"

        # the real engagement path DOES rewrite
        eng = ExecRequest(command="ffuf", args=args, approved=True, egress=True, engagement_id="e1")
        out_e, note_e = E.apply_egress_to_request(eng)
        assert out_e is not eng and out_e.args[:2] == ["-x", "http://p1:9"], out_e.args
        assert "egressing via http://p1:9" in note_e, note_e
    print("  egressed in engagement mode; lab, WinRM, capture and unasked runs untouched: PASS")


def test_identify_header_is_pinned_when_configured() -> None:
    args = ["-u", f"http://{_LAB}/FUZZ"]
    with _StubPool(["http://p1:9"], header="X-BugBounty: acme-h1-zaid"):
        eng = ExecRequest(command="ffuf", args=args, approved=True, egress=True, engagement_id="e1")
        out, _ = E.apply_egress_to_request(eng)
        assert "-H" in out.args and "X-BugBounty: acme-h1-zaid" in out.args, out.args
    print("  the program identify header is pinned while the IP rotates: PASS")


# --------------------------------------------------------------------------- #
# 3. it never lies about whether it worked
# --------------------------------------------------------------------------- #
def test_a_direct_run_says_so() -> None:
    def notes_for(**kw) -> list[str]:
        return E.run_notes(ExecRequest(approved=True, egress=True, **kw))

    with _StubPool([]):  # engagement exists but NO pool
        no_pool = notes_for(command="ffuf", args=["-u", "http://x"], engagement_id="e1")
        assert any("no egress pool is configured" in n for n in no_pool), no_pool

    with _StubPool(["http://p1:9"]):
        # a tool with no known proxy flag, even with a pool, goes direct and says so
        no_flag = notes_for(command="python3", args=["x.py"], engagement_id="e1")
        assert any("no known proxy flag" in n and "direct from the sandbox IP" in n
                   for n in no_flag), no_flag

        lab = notes_for(command="ffuf", args=["-u", "http://x"])
        assert any("engagement mode only" in n for n in lab), lab

        win = notes_for(command="Get-Process", args=[], windows_profile_id="w1")
        assert any("not available over WinRM" in n for n in win), win

        cap = notes_for(command="ffuf", args=["-u", "http://x"], engagement_id="e1", proxy=True)
        assert any("already routes through the recording proxy" in n for n in cap), cap

    # POSITIVE CONTROL — silent when egress was not asked for
    quiet = E.run_notes(ExecRequest(command="ffuf", args=["-u", "http://x"], approved=True))
    assert quiet == [], quiet
    print("  every direct path announces itself; an unasked run stays silent: PASS")


# --------------------------------------------------------------------------- #
# 4. the pool is a credential — never leaked in a note or the record
# --------------------------------------------------------------------------- #
def test_a_proxy_url_credential_is_masked_everywhere_it_could_be_recorded() -> None:
    assert E._mask_proxy_url("http://user:s3cret@host:8080") == "http://host:8080"
    assert E._mask_proxy_url("socks5://a:b@1.2.3.4:1080") == "socks5://1.2.3.4:1080"
    assert E._mask_proxy_url("http://host:8080") == "http://host:8080"  # nothing to strip

    # the note apply_egress emits never contains the secret
    _, note = E.apply_egress("curl", ["http://x"], "http://user:s3cret@host:8080")
    assert "s3cret" not in note and "user" not in note and "host:8080" in note, note

    # and the request-level note is masked too
    with _StubPool(["http://joe:hunter2@10.0.0.9:3128"]):
        eng = ExecRequest(command="ffuf", args=["-u", "http://x"], approved=True, egress=True,
                          engagement_id="e1")
        _, rnote = E.apply_egress_to_request(eng)
        assert "hunter2" not in rnote and "joe" not in rnote, rnote
        assert "10.0.0.9:3128" in rnote, rnote
    print("  a proxy URL's credentials never reach a note or a record: PASS")


# --------------------------------------------------------------------------- #
# 5. rotation — round-robin, skip banned, None when none usable
# --------------------------------------------------------------------------- #
def test_rotation_round_robins_skips_banned_and_reports_exhaustion() -> None:
    with _StubPool(["http://a:9", "http://b:9", "http://c:9"]):
        picks = [EG.pick("e1") for _ in range(4)]
        assert picks[:3] == ["http://a:9", "http://b:9", "http://c:9"], picks
        assert picks[3] == "http://a:9", f"rotation did not wrap: {picks}"

        EG.reset("e1")
        EG.mark_banned("e1", "http://a:9")
        after = [EG.pick("e1") for _ in range(2)]
        assert "http://a:9" not in after, f"a banned IP was still picked: {after}"

        EG.mark_banned("e1", "http://b:9")
        EG.mark_banned("e1", "http://c:9")
        assert EG.pick("e1") is None, "all IPs banned but pick() still returned one"

    with _StubPool([]):
        assert EG.pick("e1") is None, "an empty pool must pick nothing"
    print("  rotation wraps, skips banned, and returns None when exhausted: PASS")


# --------------------------------------------------------------------------- #
# 6. the pool never lands on the browser-facing record (credential isolation, DB-backed)
# --------------------------------------------------------------------------- #
def test_the_pool_is_held_only_by_egress_config_never_on_the_record() -> None:
    # ignore_cleanup_errors: sqlite WAL connections linger on Windows (sqlite3's `with` commits
    # but does not close), so the temp file may still be open at teardown — not a test failure.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        db = str(Path(td) / "sessions.db")
        orig = ENG.DB_PATH
        ENG.DB_PATH = db  # _connect() reads this module global
        try:
            ENG.init_db()
            with ENG._connect() as conn:
                conn.execute(
                    "INSERT INTO engagement_mode (engagement_id, target, authorization, active, "
                    "entered_at) VALUES ('E1', 'acme.com', 'ok', 1, '2026-08-15T00:00:00Z')"
                )
            ENG.set_egress("E1", ["http://joe:hunter2@10.0.0.9:3128"], "X-BB: zaid")

            pool, header = ENG.egress_config("E1")
            assert pool == ["http://joe:hunter2@10.0.0.9:3128"] and header == "X-BB: zaid"

            # the safe projections carry size + NAME only, never the URL or the header value
            assert ENG.egress_pool_size("E1") == 1
            assert ENG.egress_identify_name("E1") == "X-BB"
            assert "hunter2" not in ENG.egress_identify_name("E1")

            rec = ENG.get_active("E1")
            assert rec is not None
            blob = rec.model_dump_json()
            assert "hunter2" not in blob and "10.0.0.9" not in blob, (
                "an egress proxy credential leaked onto the EngagementRecord"
            )

            # a bare-name identify header is refused (a program wants a real 'Name: value')
            try:
                ENG.set_egress("E1", [], "just-a-name")
                raise AssertionError("a bare-name identify header was accepted")
            except ValueError:
                pass
        finally:
            ENG.DB_PATH = orig
    print("  the pool is held only by egress_config; the record shows size + name only: PASS")


if __name__ == "__main__":
    test_egress_only_ever_prepends_and_still_faces_every_gate()
    test_the_egress_rewrite_cancels_a_prevalidated_verdict()
    test_egress_is_engagement_mode_only_and_opt_in()
    test_identify_header_is_pinned_when_configured()
    test_a_direct_run_says_so()
    test_a_proxy_url_credential_is_masked_everywhere_it_could_be_recorded()
    test_rotation_round_robins_skips_banned_and_reports_exhaustion()
    test_the_pool_is_held_only_by_egress_config_never_on_the_record()
    print("ALL egress safety invariants hold")
