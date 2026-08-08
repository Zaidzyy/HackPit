import json

import alternatives
import llm


# entry_commands reads step["code"][].cmd — the fixture must use that exact shape.
_ENTRY = {
    "id": "kb-union-sqli", "title": "Manual UNION SQLi", "category": "web",
    "steps": [{"n": 1, "code": [
        {"lang": "bash", "cmd": "curl 'http://EXAMPLE/?id=1 UNION SELECT 1,2'"}]}],
}
BY_ID = {"kb-union-sqli": _ENTRY}


def _search(_q):
    return [{"id": "kb-union-sqli", "title": "Manual UNION SQLi"}]


def _patch_chat(monkeypatch, payload):
    monkeypatch.setattr(llm, "load_config",
                        lambda: {"model": "opus", "provider": "claude-agent-sdk"})
    monkeypatch.setattr(llm, "chat", lambda *a, **k: json.dumps(payload))


def test_grounded_alternative_uses_entry_commands_verbatim(monkeypatch):
    _patch_chat(monkeypatch, {
        "choice": "grounded", "entry_id": "kb-union-sqli", "title": "Manual UNION SQLi",
        "verdict": {"recommendation": "situational", "summary": "quieter than sqlmap",
                    "factors": ["stealth"]},
    })
    out = alternatives.best_alternative(
        {"title": "sqlmap dump", "cmd": "sqlmap -u http://t --dump", "entry_id": "kb-sqlmap"},
        goal="dump the db", target="target.test", scope=None, by_id=BY_ID, search_fn=_search)
    alt = out["alternative"]
    assert alt is not None and alt["kind"] == "grounded"
    assert alt["entry_id"] == "kb-union-sqli"
    assert alt["commands"] and "UNION SELECT" in alt["commands"][0]["cmd"]
    # verbatim from the entry, not the model's own — so not marked unverified
    assert alt["commands"][0].get("unverified") is not True


def test_tuned_alternative_is_capped_and_unverified(monkeypatch):
    _patch_chat(monkeypatch, {
        "choice": "tuned", "title": "sqlmap + evasion",
        "commands": [{"lang": "bash",
                      "cmd": "sqlmap -u http://EXAMPLE --dump --random-agent --tamper=space2comment"}],
        "verdict": {"recommendation": "alternative", "summary": "adds WAF evasion",
                    "factors": ["evasion"]},
    })
    out = alternatives.best_alternative(
        {"title": "sqlmap dump", "cmd": "sqlmap -u http://t --dump", "entry_id": "kb-sqlmap"},
        goal="dump the db", target="target.test", scope=None, by_id={}, search_fn=lambda q: [])
    alt = out["alternative"]
    assert alt is not None and alt["kind"] == "ai_suggested"
    assert alt["entry_id"] == ""
    assert alt["commands"][0]["unverified"] is True


def test_choice_none_returns_no_alternative(monkeypatch):
    _patch_chat(monkeypatch, {"choice": "none",
                              "verdict": {"recommendation": "primary",
                                          "summary": "primary is best", "factors": []}})
    out = alternatives.best_alternative(
        {"title": "sqlmap", "cmd": "sqlmap -u http://t --dump", "entry_id": "kb-sqlmap"},
        goal="dump", target="t", scope=None, by_id={}, search_fn=lambda q: [])
    assert out["alternative"] is None
    assert out["verdict"]["recommendation"] == "primary"


def test_verdict_never_carries_a_gate_field(monkeypatch):
    _patch_chat(monkeypatch, {"choice": "none",
                              "verdict": {"recommendation": "primary", "summary": "ok",
                                          "approved": True, "dangerous_ack": True}})
    out = alternatives.best_alternative(
        {"title": "x", "cmd": "x", "entry_id": ""}, goal="g", target=None, scope=None,
        by_id={}, search_fn=lambda q: [])
    for banned in ("approved", "dangerous_ack"):
        assert banned not in out["verdict"]


def test_llm_unreachable_is_soft(monkeypatch):
    monkeypatch.setattr(llm, "load_config",
                        lambda: {"model": "opus", "provider": "claude-agent-sdk"})

    def _boom(*a, **k):
        raise llm.LLMError("offline")

    monkeypatch.setattr(llm, "chat", _boom)
    out = alternatives.best_alternative(
        {"title": "x", "cmd": "x", "entry_id": ""}, goal="g", target=None, scope=None,
        by_id={}, search_fn=lambda q: [])
    assert out["alternative"] is None
    assert "unreachable" in out["verdict"]["summary"]


def test_never_invents_an_entry_id(monkeypatch):
    # model cites an id that is not in by_id → must NOT become a grounded alt with a fake id
    _patch_chat(monkeypatch, {"choice": "grounded", "entry_id": "kb-does-not-exist",
                              "title": "ghost", "commands": [],
                              "verdict": {"recommendation": "primary", "summary": "n/a",
                                          "factors": []}})
    out = alternatives.best_alternative(
        {"title": "x", "cmd": "x", "entry_id": ""}, goal="g", target=None, scope=None,
        by_id=BY_ID, search_fn=_search)
    alt = out["alternative"]
    assert alt is None or alt["kind"] != "grounded" or alt["entry_id"] in BY_ID


def test_alternative_commands_are_scope_adapted(monkeypatch):
    # The alternative goes through the SAME target/scope machinery as a primary:
    # substitute_target repoints an out-of-scope host to the engagement target.
    _patch_chat(monkeypatch, {
        "choice": "tuned", "title": "hit an out-of-scope host",
        "commands": [{"lang": "bash", "cmd": "curl http://evil-out-of-scope.test/x"}],
        "verdict": {"recommendation": "situational", "summary": "x", "factors": []},
    })
    out = alternatives.best_alternative(
        {"title": "scan", "cmd": "curl http://target.test/", "entry_id": ""},
        goal="scan", target="target.test", scope="target.test", by_id={},
        search_fn=lambda q: [])
    alt = out["alternative"]
    assert alt is not None
    cmd = alt["commands"][0]["cmd"]
    assert "evil-out-of-scope.test" not in cmd   # scope machinery rewrote the foreign host
    assert "target.test" in cmd
