from fastapi.testclient import TestClient

import alternatives
import main


def test_alternative_endpoint_returns_verdict_and_alternative(monkeypatch):
    monkeypatch.setattr(alternatives, "best_alternative", lambda primary, **kw: {
        "alternative": {"kind": "ai_suggested", "entry_id": "", "entry_title": "",
                        "title": "tuned",
                        "commands": [{"lang": "bash", "cmd": "sqlmap --tamper=x",
                                      "unverified": True}]},
        "verdict": {"recommendation": "alternative", "summary": "adds evasion",
                    "factors": ["evasion"], "model_used": "opus",
                    "provider": "claude-agent-sdk"},
    })
    client = TestClient(main.app)
    r = client.post("/attack-path/alternative", json={
        "goal": "dump the db", "target": "target.test",
        "step_title": "sqlmap dump", "step_cmd": "sqlmap -u http://target.test --dump",
        "step_entry_id": "kb-sqlmap"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"]["recommendation"] == "alternative"
    assert body["alternative"]["kind"] == "ai_suggested"
    assert body["alternative"]["commands"][0]["unverified"] is True


def test_alternative_endpoint_requires_goal():
    client = TestClient(main.app)
    r = client.post("/attack-path/alternative", json={"goal": "  ", "step_cmd": "x"})
    assert r.status_code == 400
