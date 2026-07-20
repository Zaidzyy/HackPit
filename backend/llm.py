"""HackPit LLM layer — provider-swappable chat completion for generative features.

The first generative feature (guided attack paths) needs a chat LLM to compose
an ordered, KB-grounded walkthrough. This module isolates *how* we talk to an
LLM from *what* we ask it, so the provider can be swapped without touching the
feature code.

Design
------
* **Default = local Ollama** (`/api/chat`, model from config, default
  ``qwen3:8b``). Free, offline, no key. Reasoning models that emit
  ``<think>…</think>`` are handled — the block is stripped before parsing.
* **Swappable** via a *gitignored* config (``backend/llm_config.json``) or env.
  Set ``provider`` + ``api_key`` to route to openai / anthropic / openrouter
  through a thin urllib adapter — no extra dependency, no LiteLLM needed.
* **Robust JSON parsing**: models wrap JSON in prose or ```code fences``` and
  sometimes emit a reasoning preamble. `extract_json` peels all of that off.

Nothing here imports FastAPI — it is a plain library the API layer calls.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# config — a gitignored JSON file next to this module, with env overrides
# --------------------------------------------------------------------------- #
CONFIG_PATH = Path(__file__).with_name("llm_config.json")

VALID_PROVIDERS = ("ollama", "openai", "anthropic", "openrouter")

# Default provider is LOCAL Ollama — free, offline, needs no API key.
DEFAULTS: dict[str, str] = {
    "provider": "ollama",
    "model": "qwen3:8b",
    "host": "http://localhost:11434",  # only used by the ollama provider
}

# Sensible default model per remote provider, applied when a provider is chosen
# without naming a model.
PROVIDER_DEFAULT_MODEL: dict[str, str] = {
    "ollama": "qwen3:8b",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-opus-4-8",
    "openrouter": "openai/gpt-4o-mini",
}


class LLMError(RuntimeError):
    """The LLM could not be reached or produced no usable output."""


def _read_config_file() -> dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def load_config() -> dict[str, Any]:
    """Effective config: file → env overrides → defaults (env wins over file).

    The returned dict MAY contain ``api_key`` — callers that expose it to the
    client MUST use `public_config` instead, which never includes the key.
    """
    cfg = dict(DEFAULTS)
    cfg.update(_read_config_file())

    # env overrides (handy for containerized / CI setups)
    if os.environ.get("HACKPIT_LLM_PROVIDER"):
        cfg["provider"] = os.environ["HACKPIT_LLM_PROVIDER"]
    if os.environ.get("HACKPIT_LLM_MODEL"):
        cfg["model"] = os.environ["HACKPIT_LLM_MODEL"]
    if os.environ.get("HACKPIT_LLM_API_KEY"):
        cfg["api_key"] = os.environ["HACKPIT_LLM_API_KEY"]
    if os.environ.get("HACKPIT_LLM_HOST"):
        cfg["host"] = os.environ["HACKPIT_LLM_HOST"]

    provider = str(cfg.get("provider") or "ollama").lower()
    if provider not in VALID_PROVIDERS:
        provider = "ollama"
    cfg["provider"] = provider
    if not cfg.get("model"):
        cfg["model"] = PROVIDER_DEFAULT_MODEL.get(provider, DEFAULTS["model"])
    return cfg


def public_config() -> dict[str, Any]:
    """Config safe to return to the browser — the key is reduced to a boolean."""
    cfg = load_config()
    return {
        "provider": cfg["provider"],
        "model": cfg["model"],
        "has_key": bool(cfg.get("api_key")),
    }


def save_config(
    provider: str,
    model: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Persist provider/model (+ optional key) to the gitignored config file.

    * Validates the provider.
    * Ollama needs no key; remote providers require one (a stored key is reused
      if the caller omits it, so the user can change model without re-pasting).
    * The key is written to disk but NEVER returned — the caller gets
      `public_config`.
    """
    provider = (provider or "").lower().strip()
    if provider not in VALID_PROVIDERS:
        raise ValueError(
            f"unknown provider '{provider}' — one of {', '.join(VALID_PROVIDERS)}"
        )

    existing = _read_config_file()
    out: dict[str, Any] = {"provider": provider}
    out["model"] = (model or "").strip() or PROVIDER_DEFAULT_MODEL.get(
        provider, DEFAULTS["model"]
    )

    # preserve host if previously set (ollama only)
    if existing.get("host"):
        out["host"] = existing["host"]

    if provider == "ollama":
        # local provider carries no key
        pass
    else:
        key = (api_key or "").strip()
        if not key:
            key = str(existing.get("api_key") or "").strip()
        if not key:
            raise ValueError(f"provider '{provider}' requires an api_key")
        out["api_key"] = key

    CONFIG_PATH.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return public_config()


# --------------------------------------------------------------------------- #
# transport — zero-dependency JSON POST (mirrors pipeline/embed.py's style)
# --------------------------------------------------------------------------- #
# server-busy statuses worth one retry — a local Ollama loading/serving another
# request returns these transiently (seen under concurrent load). Permanent
# errors (400 bad-request, 401/403 auth, 404, 422) are NOT retried.
_RETRY_STATUS = {502, 503, 504}
_MAX_ATTEMPTS = 2


def _post_json(
    url: str, payload: dict, headers: dict[str, str], timeout: int = 300
) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    for attempt in range(_MAX_ATTEMPTS):
        last = attempt + 1 == _MAX_ATTEMPTS
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:400]
            # Retry only transient server-busy statuses; surface the rest (incl.
            # the 400 the ollama adapter special-cases) immediately.
            if e.code in _RETRY_STATUS and not last:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise LLMError(f"{url} → HTTP {e.code}: {body}") from e
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            if not last:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise LLMError(f"cannot reach LLM endpoint {url} ({e})") from e
    raise LLMError(f"cannot reach LLM endpoint {url}")  # unreachable


# --------------------------------------------------------------------------- #
# provider adapters — each takes (system, user, cfg) and returns raw text
# --------------------------------------------------------------------------- #
def _chat_ollama(system: str, user: str, cfg: dict, max_tokens: int = 2048) -> str:
    host = str(cfg.get("host") or DEFAULTS["host"]).rstrip("/")
    # Reasoning models (qwen3 et al.) otherwise emit a long <think>…</think>
    # block that dominates the compose time. Suppress it two ways for
    # reliability: the API-level ``think: false`` flag AND qwen3's ``/no_think``
    # prompt convention. num_predict caps the output — small for short JSON,
    # larger for long-form output like reports (raised by the caller).
    payload = {
        "model": cfg["model"],
        "messages": [
            {"role": "system", "content": system + "\n/no_think"},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0.4,
            "num_ctx": 8192,
            "num_predict": max_tokens,
        },
    }
    try:
        data = _post_json(f"{host}/api/chat", payload, {})
    except LLMError as e:
        # Older Ollama builds reject an unknown ``think`` field with HTTP 400.
        # Retry without it — ``/no_think`` in the prompt still suppresses most
        # of the reasoning, and `strip_think` cleans up any that remains.
        if "HTTP 400" not in str(e):
            raise
        payload.pop("think", None)
        data = _post_json(f"{host}/api/chat", payload, {})
    msg = (data.get("message") or {}).get("content")
    if not msg:
        raise LLMError(f"Ollama returned no content: {str(data)[:200]}")
    return msg


def _chat_openai_compatible(
    system: str, user: str, cfg: dict, url: str, max_tokens: int = 2048
) -> str:
    """OpenAI Chat Completions shape — also used for OpenRouter."""
    key = cfg.get("api_key")
    if not key:
        raise LLMError("missing api_key for this provider")
    payload = {
        "model": cfg["model"],
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.4,
        "max_tokens": max_tokens,
    }
    data = _post_json(url, payload, {"Authorization": f"Bearer {key}"})
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError(f"unexpected chat response: {str(data)[:200]}") from e


def _chat_anthropic(system: str, user: str, cfg: dict, max_tokens: int = 2048) -> str:
    key = cfg.get("api_key")
    if not key:
        raise LLMError("missing api_key for anthropic")
    payload = {
        "model": cfg["model"],
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    data = _post_json(
        "https://api.anthropic.com/v1/messages",
        payload,
        {"x-api-key": key, "anthropic-version": "2023-06-01"},
    )
    try:
        blocks = data["content"]
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    except (KeyError, TypeError) as e:
        raise LLMError(f"unexpected anthropic response: {str(data)[:200]}") from e


def chat(
    system: str, user: str, cfg: dict | None = None, max_tokens: int = 2048
) -> str:
    """Route one system+user turn to the configured provider, return raw text.

    ``max_tokens`` caps the output length (num_predict for Ollama, max_tokens
    for the API providers). Keep it small for short structured output; raise it
    for long-form output like reports so they aren't truncated.
    """
    cfg = cfg or load_config()
    provider = cfg["provider"]
    if provider == "ollama":
        return _chat_ollama(system, user, cfg, max_tokens)
    if provider == "openai":
        return _chat_openai_compatible(
            system, user, cfg, "https://api.openai.com/v1/chat/completions", max_tokens
        )
    if provider == "openrouter":
        return _chat_openai_compatible(
            system,
            user,
            cfg,
            "https://openrouter.ai/api/v1/chat/completions",
            max_tokens,
        )
    if provider == "anthropic":
        return _chat_anthropic(system, user, cfg, max_tokens)
    raise LLMError(f"unsupported provider '{provider}'")


# --------------------------------------------------------------------------- #
# output cleaning — strip reasoning + peel JSON out of prose / code fences
# --------------------------------------------------------------------------- #
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def strip_think(text: str) -> str:
    """Remove ``<think>…</think>`` reasoning blocks (qwen3 et al.).

    Also drops a dangling, unclosed ``<think>`` opener when the model streamed a
    truncated reasoning block, keeping only content after the last such tag.
    """
    text = _THINK_RE.sub("", text)
    # unclosed reasoning: keep whatever follows the final <think> we can't pair.
    if "<think>" in text.lower():
        idx = text.lower().rfind("</think>")
        if idx != -1:
            text = text[idx + len("</think>") :]
    return text.strip()


def extract_json(text: str) -> Any:
    """Best-effort parse of a JSON value from a chatty LLM response.

    Handles: plain JSON, ```json fenced``` blocks, a reasoning preamble, and
    trailing prose after the JSON. Raises `LLMError` if nothing parses.
    """
    cleaned = strip_think(text).strip()

    # 1) fenced code block ```json … ``` (or bare ``` … ```)
    fence = re.search(r"```(?:json)?\s*(.+?)```", cleaned, re.DOTALL | re.IGNORECASE)
    candidates: list[str] = []
    if fence:
        candidates.append(fence.group(1).strip())
    candidates.append(cleaned)

    for cand in candidates:
        try:
            return json.loads(cand)
        except json.JSONDecodeError:
            pass

    # 2) brace-matching scan: find the first balanced {…} (or […]) object.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = cleaned.find(opener)
        while start != -1:
            depth = 0
            in_str = False
            esc = False
            for i in range(start, len(cleaned)):
                ch = cleaned[i]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == opener:
                    depth += 1
                elif ch == closer:
                    depth -= 1
                    if depth == 0:
                        blob = cleaned[start : i + 1]
                        try:
                            return json.loads(blob)
                        except json.JSONDecodeError:
                            break
            start = cleaned.find(opener, start + 1)

    raise LLMError("could not parse JSON from LLM response")
