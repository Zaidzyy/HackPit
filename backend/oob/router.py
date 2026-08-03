"""FastAPI routes for the out-of-band canary (spec §3.3-§3.5) — mounted into main.py.

Endpoints:
* ``GET    /oob``              — the canary's masked configuration, NS records to paste at the
                                 registrar, and the template catalog. The panel's whole state.
* ``POST   /oob/config``       — save the configuration. The read secret is write-only.
* ``DELETE /oob/config``       — forget the canary. Does NOT stop a server already running.
* ``POST   /oob/mint``         — mint a token for a step, and render the payloads for it.
* ``GET    /oob/tokens/{id}``  — every token minted for one engagement.
* ``POST   /oob/poll``         — fetch what is new, correlate it, file it into engagement state.
* ``POST   /oob/deploy``       — GATED: ship server.py to the configured VPS and start it.
* ``POST   /oob/verify``       — is the canary actually working? Three checks, reported each.

WHY DEPLOY LOOKS DIFFERENT FROM EVERY OTHER ROUTE HERE. It carries no destination. This module
never learns the VPS address, never passes one, and could not pass one if it wanted to: the
executor's deploy function takes no host parameter and resolves it from the config store
itself. That is the containment argument from spec §4, and it is why the route body below is
three lines — there is nothing for it to decide.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from cockpit import engagement as engagement_mod
from cockpit import executor

from . import config as oob_config
from . import poll as poll_mod
from . import templates as templates_mod
from . import tokens as tokens_mod
from . import verify as verify_mod

router = APIRouter(prefix="/oob", tags=["oob"])


class ConfigRequest(BaseModel):
    """The canary's configuration. ``read_secret`` is write-only — never returned."""

    zone: str = Field(..., description="The NS-delegated zone, e.g. oob.example.net.")
    host: str = Field(..., description="The VPS address the canary runs on.")
    answer_ip: str = Field("", description="What every A query answers with. Defaults to host.")
    http_port: int = Field(oob_config.DEFAULT_HTTP_PORT)
    dns_port: int = Field(oob_config.DEFAULT_DNS_PORT)
    ssh_user: str = Field(oob_config.DEFAULT_SSH_USER)
    ssh_port: int = Field(oob_config.DEFAULT_SSH_PORT)
    ssh_key_path: str = Field("", description="Path to a key ALREADY on this machine.")
    read_secret: str = Field(
        "", description="Bearer secret the server checks. Blank on edit keeps the stored one."
    )


class MintRequest(BaseModel):
    engagement_id: str = Field(..., description="Which engagement this canary belongs to.")
    step_id: str | None = Field(None, description="The step whose payload carries it.")
    note: str = Field("", description="What this token is testing — it becomes the finding title.")
    vuln_class: str | None = Field(None, description="Render only this class of payload.")


class DeployRequest(BaseModel):
    """Note what is NOT here: no host, user, port or key. See the module docstring."""

    approved: bool = Field(False, description="Per-call human approval. Required.")
    restart: bool = Field(True, description="Restart the daemon after shipping the file.")


class PollRequest(BaseModel):
    after: int | None = Field(
        None, description="Read from here instead of the stored cursor. Does not advance it."
    )


@router.get("")
def get_oob() -> dict[str, Any]:
    """Everything the panel needs to render, in one call. Never a secret."""
    return {
        "configured": oob_config.is_configured(),
        "config": oob_config.public(),
        "ns": oob_config.ns_delegation(),
        "templates": templates_mod.catalog(),
        "vuln_classes": list(templates_mod.VULN_CLASSES),
        "remote_dir": oob_config.REMOTE_DIR,
    }


@router.post("/config")
def post_config(req: ConfigRequest) -> dict[str, Any]:
    """Save the configuration. 400 names exactly what was wrong with it."""
    try:
        saved = oob_config.save(**req.model_dump())
    except oob_config.ConfigError as exc:
        raise HTTPException(status_code=400, detail={"gate": "oob-config", "reason": str(exc)})
    return {
        "config": saved,
        "ns": oob_config.ns_delegation(),
        "note": "nothing is deployed yet — the server still has to be shipped and started",
    }


@router.delete("/config")
def delete_config() -> dict[str, Any]:
    """Forget the canary. Deliberately explicit that this stops nothing."""
    return {
        "removed": oob_config.clear(),
        "note": "HackPit has forgotten the canary; a server already running on the VPS is "
                "still running and still listening. Stop it on the box.",
    }


@router.post("/mint")
def post_mint(req: MintRequest) -> dict[str, Any]:
    """Mint a token and render the payloads that carry it.

    Minting and rendering are one call because a rendered payload with no mint record behind
    it is a name that correlates to nothing — the hit would arrive and mean "something reached
    the internet" instead of "the payload from step 7 came back".
    """
    if not oob_config.is_configured():
        raise HTTPException(status_code=400, detail={
            "gate": "oob-config",
            "reason": "no canary is configured — a payload rendered without a zone can never "
                      "call back",
        })
    minted = tokens_mod.mint(req.engagement_id, req.step_id, req.note)
    try:
        payloads = templates_mod.render_all(minted["token"], vuln_class=req.vuln_class)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"gate": "oob-config", "reason": str(exc)})
    return {"token": minted, "zone": oob_config.zone(), "payloads": payloads}


@router.get("/tokens/{engagement_id}")
def get_tokens(engagement_id: str) -> dict[str, Any]:
    """Every token minted for one engagement, newest first."""
    return {"engagement_id": engagement_id, "tokens": tokens_mod.list_for(engagement_id)}


@router.post("/poll")
def post_poll(req: PollRequest) -> dict[str, Any]:
    """Fetch what is new, correlate it, and file it into engagement state.

    The engagement -> session mapping is resolved HERE, from every engagement rather than only
    the active ones: an out-of-band hit routinely lands after the engagement that caused it has
    been exited, and dropping those is the evidence loss this whole part exists to stop.
    """
    try:
        return poll_mod.poll(engagement_mod.session_ids(), after=req.after)
    except poll_mod.PollError as exc:
        raise HTTPException(status_code=502, detail={"gate": "oob-poll", "reason": str(exc)})


@router.post("/deploy")
def post_deploy(req: DeployRequest) -> dict[str, Any]:
    """GATED: ship server.py to the configured VPS and start it.

    A new remote-execution path, so it goes through the executor exactly like every other
    remote command — and it is passed no destination, because there is no parameter for one.
    """
    try:
        return executor.deploy_oob_canary(approved=req.approved, restart=req.restart)
    except executor.OOBDeployRefused as exc:
        raise HTTPException(status_code=403, detail={"gate": exc.gate, "reason": exc.reason})


@router.post("/verify")
def post_verify() -> dict[str, Any]:
    """Is the canary working? Each check reports itself; NOT-RUN is never a pass."""
    return verify_mod.verify()
