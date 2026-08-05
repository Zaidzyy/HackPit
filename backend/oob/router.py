"""FastAPI routes for the out-of-band canary (spec §3.3-§3.5) — mounted into main.py.

Endpoints:
* ``GET    /oob``                     — both backends' masked state, NS records, the auto-poll
                                        setting, and the template catalog. The panel's whole state.
* ``POST   /oob/config``              — save the self-hosted configuration. The read secret is write-only.
* ``DELETE /oob/config``              — forget the self-hosted canary. Does NOT stop a running server.
* ``POST   /oob/interactsh/register`` — start/rotate an interact.sh session. Secret/keypair write-only.
* ``DELETE /oob/interactsh``          — deregister and forget the interact.sh session.
* ``POST   /oob/autopoll``            — set the read-only auto-poll toggle + interval.
* ``POST   /oob/mint``                — mint under every configured backend and render each payload set.
* ``GET    /oob/tokens/{id}``         — every self-hosted token minted for one engagement.
* ``POST   /oob/poll``                — sweep BOTH backends, correlate, file into engagement state.
* ``POST   /oob/deploy``              — GATED: ship server.py to the configured VPS and start it.
* ``POST   /oob/verify``              — are the canaries working? Self-hosted triad + interact.sh, each reported.

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
from . import interactsh as interactsh_mod
from . import poll as poll_mod
from . import settings as settings_mod
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


class InteractshRegisterRequest(BaseModel):
    """Start (or rotate) an interact.sh session. The secret/keypair are minted server-side."""

    server: str = Field(
        interactsh_mod.DEFAULT_SERVER, description="interact.sh server host, e.g. oast.fun."
    )
    auth_token: str = Field(
        "", description="Auth token for a self-hosted interactsh-server. Blank for the public one."
    )


class AutopollRequest(BaseModel):
    enabled: bool = Field(..., description="Whether the background sweep files callbacks on its own.")
    interval: int = Field(
        settings_mod.DEFAULT_INTERVAL, description="Seconds between sweeps; floored server-side."
    )


@router.get("")
def get_oob() -> dict[str, Any]:
    """Everything the panel needs to render, in one call. Never a secret.

    Carries BOTH backends: the self-hosted canary's masked config + NS records, and the
    interact.sh session status (masked — correlation-id prefix only, never the secret/keypair),
    plus the auto-poll setting.
    """
    return {
        "configured": oob_config.is_configured(),
        "config": oob_config.public(),
        "ns": oob_config.ns_delegation(),
        "interactsh": interactsh_mod.session_public(),
        "interactsh_default_server": interactsh_mod.DEFAULT_SERVER,
        "autopoll": settings_mod.get(),
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
    """Mint under EVERY configured backend and render the payloads that carry each callback.

    Minting and rendering are one call because a rendered payload with no mint record behind
    it is a name that correlates to nothing — the hit would arrive and mean "something reached
    the internet" instead of "the payload from step 7 came back". Both backends tie to the same
    engagement/step/note, so a callback on either resolves to the same test; the response labels
    the payloads by backend so the operator pastes whichever (or both).
    """
    self_hosted = oob_config.is_configured()
    ish = interactsh_mod.is_registered()
    if not self_hosted and not ish:
        raise HTTPException(status_code=400, detail={
            "gate": "oob-config",
            "reason": "no canary is configured — set up the self-hosted canary or register an "
                      "interact.sh session before minting a payload",
        })

    backends: dict[str, Any] = {"self_hosted": None, "interactsh": None}
    if self_hosted:
        minted = tokens_mod.mint(req.engagement_id, req.step_id, req.note)
        try:
            payloads = templates_mod.render_all(minted["token"], vuln_class=req.vuln_class)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"gate": "oob-config", "reason": str(exc)})
        backends["self_hosted"] = {
            "token": minted, "zone": oob_config.zone(), "payloads": payloads,
        }
    if ish:
        try:
            generated = interactsh_mod.generate(req.engagement_id, req.step_id, req.note)
            payloads = templates_mod.render_all(host=generated["host"], vuln_class=req.vuln_class)
        except (interactsh_mod.InteractshError, ValueError) as exc:
            raise HTTPException(status_code=400, detail={"gate": "oob-interactsh", "reason": str(exc)})
        backends["interactsh"] = {
            "host": generated["host"], "suffix": generated["suffix"], "payloads": payloads,
        }
    return {"backends": backends}


@router.post("/interactsh/register")
def post_interactsh_register(req: InteractshRegisterRequest) -> dict[str, Any]:
    """Start or rotate an interact.sh session. Returns the masked status — never a secret."""
    try:
        return interactsh_mod.register(server_host=req.server, auth_token=req.auth_token)
    except interactsh_mod.InteractshError as exc:
        raise HTTPException(status_code=502, detail={"gate": "oob-interactsh", "reason": str(exc)})


@router.delete("/interactsh")
def delete_interactsh() -> dict[str, Any]:
    """Deregister on the interact.sh server and forget the session locally."""
    return {
        "removed": interactsh_mod.deregister(),
        "note": "the interact.sh session is forgotten; payloads already minted under it will no "
                "longer correlate",
    }


@router.post("/autopoll")
def post_autopoll(req: AutopollRequest) -> dict[str, Any]:
    """Set the auto-poll toggle + interval. Read-only automation — files callbacks, sends nothing."""
    return {"autopoll": settings_mod.set(enabled=req.enabled, interval=req.interval)}


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
    return poll_mod.poll_all(engagement_mod.session_ids(), after=req.after)


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
