"""The three graph second-opinion endpoints (AD / cloud / killchain) each hand the edge's
command to the shared engine and return {alternative, verdict}. The engine itself is unit-tested
in test_alternatives.py; here we assert the endpoints exist, pass the primary through, and
return the shaped result."""
import pytest
from fastapi.testclient import TestClient

import alternatives
import main


@pytest.fixture
def client(monkeypatch):
    captured = {}

    def _fake(primary, **kw):
        captured["primary"] = primary
        captured["goal"] = kw.get("goal")
        return {
            "alternative": {"kind": "grounded", "entry_id": "kb-x", "entry_title": "X",
                            "title": "X", "commands": [{"lang": "bash", "cmd": "tool --run"}]},
            "verdict": {"recommendation": "alternative", "summary": "different route",
                        "factors": [], "model_used": "opus", "provider": "claude-agent-sdk"},
        }

    monkeypatch.setattr(alternatives, "best_alternative", _fake)
    c = TestClient(main.app)
    c.captured = captured
    return c


@pytest.mark.parametrize("path,ctx", [
    ("/cockpit/ad/alternative", "DCSync from owned principal"),
    ("/cockpit/cloud/alternative", "iam:PassRole to admin"),
    ("/cockpit/killchain/alternative", "web foothold -> cloud metadata"),
])
def test_graph_alternative_endpoint(client, path, ctx):
    r = client.post(path, json={"title": "primary tech", "cmd": "primary --cmd",
                                "entry_id": "kb-primary", "context": ctx})
    assert r.status_code == 200
    body = r.json()
    assert body["alternative"]["kind"] == "grounded"
    assert body["verdict"]["recommendation"] == "alternative"
    # the edge's command + context were handed to the engine as the primary + goal
    assert client.captured["primary"]["cmd"] == "primary --cmd"
    assert client.captured["goal"] == ctx
