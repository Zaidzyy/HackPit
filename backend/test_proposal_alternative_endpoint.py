from fastapi.testclient import TestClient

import alternatives
import main
from cockpit import proposals as cockpit_proposals


def _fake_alt(monkeypatch):
    monkeypatch.setattr(alternatives, "best_alternative", lambda primary, **kw: {
        "alternative": {"kind": "grounded", "entry_id": "kb-x", "entry_title": "X",
                        "title": "X", "commands": [{"lang": "bash", "cmd": "sqlmap --dump"}]},
        "verdict": {"recommendation": "alternative", "summary": "grounded is better",
                    "factors": [], "model_used": "opus", "provider": "claude-agent-sdk"},
    })


def test_proposal_alternative_returns_candidate(monkeypatch):
    _fake_alt(monkeypatch)
    p = cockpit_proposals.propose("nmap", ["-sV", "target.test"],
                                  rationale="fingerprint services", source="operator")
    client = TestClient(main.app)
    r = client.post(f"/cockpit/proposals/{p.id}/alternative")
    assert r.status_code == 200
    body = r.json()
    assert body["alternative"]["kind"] == "grounded"
    assert body["verdict"]["recommendation"] == "alternative"


def test_proposal_alternative_unknown_id_404():
    client = TestClient(main.app)
    r = client.post("/cockpit/proposals/does-not-exist/alternative")
    assert r.status_code == 404


def test_proposal_model_still_has_no_approval_field():
    # The second-opinion surface must not have added a gate field to the queue's model.
    fields = set(cockpit_proposals.Proposal.model_fields)
    assert "approved" not in fields
    assert "dangerous_ack" not in fields


def test_queue_list_and_review_shape_the_viewer_depends_on():
    # The :proposals viewer reads command_line + gate_preview from the list, and calls review.
    cockpit_proposals.clear()
    p = cockpit_proposals.propose("nmap", ["-sV", "target.test"],
                                  rationale="fingerprint", source="operator")
    client = TestClient(main.app)

    rows = client.get("/cockpit/proposals").json()
    assert any(r["id"] == p.id for r in rows)
    row = next(r for r in rows if r["id"] == p.id)
    assert row["command_line"] == "nmap -sV target.test"
    assert set(row["gate_preview"]) >= {"would_refuse", "gate", "reason", "dangerous_flags"}
    assert row["status"] == "pending"

    reviewed = client.post(f"/cockpit/proposals/{p.id}/review?status=approved&note=ok").json()
    assert reviewed["status"] == "approved"
    # reviewing does NOT run — the payload says so, and there is no execution state
    assert "RUN" in reviewed["note"].upper()

    approved = client.get("/cockpit/proposals?status=approved").json()
    assert any(r["id"] == p.id for r in approved)
    assert all(r["status"] == "approved" for r in approved)
