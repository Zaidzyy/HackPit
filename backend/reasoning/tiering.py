"""2.8 — model-tier routing (a config lever, default OFF and inert).

Reasoning depth is mostly the base model. A small local model caps the ceiling no matter how good
the scaffolding is — so the honest lever is: let the HARD proposal step be routed to a more
capable model / higher thinking budget while routine steps use the cheap/local one. This is wired
as pure configuration with a safe default: unset means every step uses the base config exactly as
before, byte-for-byte. No behavior changes until an operator opts in.

The config lives in ``llm_config.json`` under an optional ``reasoning_tiers`` key:

    "reasoning_tiers": {
        "hard":    {"model": "claude-opus-5", "num_predict": 1200},
        "routine": {}
    }

:func:`select` merges the named tier's overrides onto the base config. It selects config; it does
not call a model and does not execute anything.
"""

from __future__ import annotations

from typing import Any

# Which proposal steps count as "hard" — worth the more capable tier when one is configured.
HARD_STEPS = frozenset({"exploit", "privesc", "chain", "critic", "hard"})


def tier_for(step_kind: str) -> str:
    """Map a step kind to a tier name. Unknown/plain steps are 'routine'."""
    return "hard" if (step_kind or "").strip().lower() in HARD_STEPS else "routine"


def select(cfg: dict[str, Any], step_kind: str = "routine") -> dict[str, Any]:
    """Return the LLM config to use for this step.

    With no ``reasoning_tiers`` configured, returns ``cfg`` UNCHANGED — the default-safe path
    that a test asserts leaves behavior identical. With tiers configured, the matching tier's
    keys are merged over a copy of the base config, so an operator can point hard steps at a
    bigger model without touching routine ones.
    """
    tiers = (cfg or {}).get("reasoning_tiers")
    if not isinstance(tiers, dict) or not tiers:
        return cfg
    tier = tier_for(step_kind)
    overrides = tiers.get(tier)
    if not isinstance(overrides, dict) or not overrides:
        return cfg
    merged = dict(cfg)
    merged.update(overrides)
    # keep the lever itself out of the config handed to the LLM client
    merged.pop("reasoning_tiers", None)
    return merged


def active(cfg: dict[str, Any]) -> bool:
    """True when tier routing is configured (for the UI/report to show the lever is engaged)."""
    tiers = (cfg or {}).get("reasoning_tiers")
    return isinstance(tiers, dict) and bool(tiers)
