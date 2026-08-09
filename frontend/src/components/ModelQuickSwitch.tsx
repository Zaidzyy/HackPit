"use client";

import { useState } from "react";
import { getOllamaModels, setLLMConfig } from "@/lib/api";

/** claude-agent-sdk aliases — no API key needed (uses the machine's Claude Code login). */
const AGENT_SDK_MODELS = ["opus", "sonnet", "haiku"];

/**
 * The launcher's llm status cell, made into a quick model switcher.
 *
 * Only the NO-KEY providers are switchable inline — claude-agent-sdk (opus/sonnet/haiku) and the
 * local Ollama models — so no secret is ever entered here and the rail's payload stays status-only
 * (test_home_summary still holds). Anything that needs a provider/API-key change routes to the
 * full settings modal via "settings…". Selecting a model writes the GLOBAL /llm-config, which every
 * generative feature (attack path, second opinion, chat) then composes with.
 */
export function ModelQuickSwitch({
  provider,
  model,
  tone,
  onOpenSettings,
  onModelChanged,
}: {
  provider: string;
  model: string;
  tone: "up" | "down" | "warn" | "unknown";
  onOpenSettings: () => void;
  onModelChanged?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [prov, setProv] = useState(provider);
  const [mod, setMod] = useState(model);
  const [ollama, setOllama] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (next && ollama === null) {
      try {
        setOllama((await getOllamaModels()).models);
      } catch {
        setOllama([]);
      }
    }
  }

  async function pick(p: string, m: string) {
    if (busy) return;
    setBusy(true);
    try {
      const c = await setLLMConfig({ provider: p, model: m });
      setProv(c.provider);
      setMod(c.model);
      setOpen(false);
      onModelChanged?.();
    } catch {
      /* keep the menu open so the operator can retry or pick another */
    } finally {
      setBusy(false);
    }
  }

  const label = prov === "ollama" ? "local" : prov || "llm";
  return (
    <div className="hp-st hp-st-llm">
      <button
        type="button"
        className="hp-st-llm-btn"
        onClick={toggle}
        aria-expanded={open}
        title="switch model"
      >
        <span className={`hp-dot hp-dot-${tone}`} aria-hidden />
        <span>
          {label}&nbsp; <b>{mod || "not configured"}</b>
        </span>
        <span className="hp-st-llm-caret" aria-hidden>
          {open ? "▲" : "▾"}
        </span>
      </button>

      {open && (
        <div className="hp-st-llm-menu" role="menu">
          <div className="hp-st-llm-group">claude-agent-sdk</div>
          {AGENT_SDK_MODELS.map((m) => (
            <button
              key={`sdk-${m}`}
              type="button"
              className={`hp-st-llm-item${
                prov === "claude-agent-sdk" && mod === m ? " is-active" : ""
              }`}
              disabled={busy}
              onClick={() => pick("claude-agent-sdk", m)}
            >
              {m}
            </button>
          ))}

          <div className="hp-st-llm-group">local · ollama</div>
          {ollama === null ? (
            <div className="hp-st-llm-empty">loading…</div>
          ) : ollama.length === 0 ? (
            <div className="hp-st-llm-empty">no local models pulled</div>
          ) : (
            ollama.map((m) => (
              <button
                key={`ol-${m}`}
                type="button"
                className={`hp-st-llm-item${
                  prov === "ollama" && mod === m ? " is-active" : ""
                }`}
                disabled={busy}
                onClick={() => pick("ollama", m)}
              >
                {m}
              </button>
            ))
          )}

          <button
            type="button"
            className="hp-st-llm-item hp-st-llm-more"
            onClick={() => {
              setOpen(false);
              onOpenSettings();
            }}
          >
            settings… (other providers / API key)
          </button>
        </div>
      )}
    </div>
  );
}
