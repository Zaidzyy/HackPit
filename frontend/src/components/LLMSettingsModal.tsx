"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ApiError, setLLMConfig, type LLMConfig } from "@/lib/api";
import { useReducedMotion } from "@/lib/useReducedMotion";

type Provider = {
  value: string;
  label: string;
  defaultModel: string;
  needsKey: boolean;
  note: string;
};

const PROVIDERS: Provider[] = [
  {
    value: "ollama",
    label: "Local Ollama",
    defaultModel: "qwen3:8b",
    needsKey: false,
    note: "Free & offline. Runs on your machine — no key, nothing leaves the host.",
  },
  {
    value: "openai",
    label: "OpenAI",
    defaultModel: "gpt-4o-mini",
    needsKey: true,
    note: "Uses the OpenAI Chat Completions API.",
  },
  {
    value: "anthropic",
    label: "Anthropic",
    defaultModel: "claude-opus-4-8",
    needsKey: true,
    note: "Uses the Anthropic Messages API.",
  },
  {
    value: "openrouter",
    label: "OpenRouter",
    defaultModel: "openai/gpt-4o-mini",
    needsKey: true,
    note: "Routes to many models through one OpenRouter key.",
  },
  {
    value: "claude-agent-sdk",
    label: "Claude (Agent SDK)",
    defaultModel: "sonnet",
    needsKey: false,
    note:
      "Uses your local Claude subscription (Claude Code login) — no key. " +
      "Draws on your monthly Agent SDK credit. Falls back to local Ollama " +
      "if it’s unavailable.",
  },
];

const byValue = (v: string) =>
  PROVIDERS.find((p) => p.value === v) ?? PROVIDERS[0];

/**
 * LLM provider settings. Pick a provider (default local Ollama, no key), a
 * model, and — for remote providers — paste an API key. The key is POSTed once
 * to /llm-config and is NEVER stored in the browser; the response only reports
 * whether a key is held server-side.
 */
export function LLMSettingsModal({
  open,
  config,
  onClose,
  onSaved,
}: {
  open: boolean;
  config: LLMConfig | null;
  onClose: () => void;
  onSaved: (c: LLMConfig) => void;
}) {
  const reduced = useReducedMotion();

  const [provider, setProvider] = useState("ollama");
  const [model, setModel] = useState("qwen3:8b");
  const [apiKey, setApiKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const active = byValue(provider);

  // Seed the form from the live config whenever the modal opens.
  useEffect(() => {
    if (!open) return;
    const p = config?.provider ?? "ollama";
    setProvider(p);
    setModel(config?.model ?? byValue(p).defaultModel);
    setApiKey("");
    setError(null);
    setSaving(false);
  }, [open, config]);

  // Esc to close + lock body scroll while open.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKey);
    };
  }, [open, onClose]);

  function pickProvider(v: string) {
    setProvider(v);
    // Suggest the provider's default model unless it's the current provider.
    setModel(v === config?.provider ? config.model : byValue(v).defaultModel);
    setError(null);
  }

  function save() {
    if (saving) return;
    const needsKey = active.needsKey && !config?.has_key && !apiKey.trim();
    if (needsKey) {
      setError(`${active.label} needs an API key.`);
      return;
    }
    setSaving(true);
    setError(null);
    setLLMConfig({
      provider,
      model: model.trim() || active.defaultModel,
      api_key: apiKey.trim() || undefined,
    })
      .then((c) => {
        onSaved(c);
        setSaving(false);
        onClose();
      })
      .catch((err: unknown) => {
        setSaving(false);
        setError(err instanceof ApiError ? err.message : "Couldn’t save settings.");
      });
  }

  const keyStored = config?.has_key && provider === config.provider;

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="hp-set-overlay"
          role="dialog"
          aria-modal="true"
          aria-label="LLM settings"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: reduced ? 0 : 0.15 }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) onClose();
          }}
        >
          <motion.div
            className="hp-set-panel"
            initial={{ opacity: 0, y: reduced ? 0 : -8, scale: reduced ? 1 : 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: reduced ? 0 : -8, scale: reduced ? 1 : 0.98 }}
            transition={{ duration: reduced ? 0 : 0.18, ease: "easeOut" }}
          >
            <header className="hp-set-head">
              <h2 className="hp-set-title">LLM settings</h2>
              <button
                type="button"
                className="hp-set-close"
                onClick={onClose}
                aria-label="Close"
              >
                ✕
              </button>
            </header>

            <div className="hp-set-body">
              <label className="hp-set-label">provider</label>
              <div className="hp-set-providers">
                {PROVIDERS.map((p) => (
                  <button
                    key={p.value}
                    type="button"
                    className={`hp-set-provider${
                      provider === p.value ? " is-on" : ""
                    }`}
                    onClick={() => pickProvider(p.value)}
                  >
                    <span className="hp-set-provider-label">{p.label}</span>
                    {!p.needsKey && (
                      <span className="hp-set-provider-tag">
                        {p.value === "ollama" ? "default · no key" : "local · no key"}
                      </span>
                    )}
                  </button>
                ))}
              </div>
              <p className="hp-set-note">{active.note}</p>

              <label className="hp-set-label" htmlFor="hp-set-model">
                model
              </label>
              <input
                id="hp-set-model"
                className="hp-set-input"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder={active.defaultModel}
                spellCheck={false}
                autoComplete="off"
              />

              {active.needsKey && (
                <>
                  <label className="hp-set-label" htmlFor="hp-set-key">
                    api key
                  </label>
                  <input
                    id="hp-set-key"
                    className="hp-set-input"
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={
                      keyStored ? "•••••••• (stored — leave blank to keep)" : "paste key"
                    }
                    spellCheck={false}
                    autoComplete="off"
                  />
                  <p className="hp-set-keynote">
                    Sent once to the backend, stored server-side only —{" "}
                    <b>never kept in the browser</b>.
                  </p>
                </>
              )}

              {error && <p className="hp-set-error hp-note-err">{error}</p>}
            </div>

            <footer className="hp-set-foot">
              <button
                type="button"
                className="hp-set-cancel"
                onClick={onClose}
                disabled={saving}
              >
                cancel
              </button>
              <button
                type="button"
                className="hp-set-save"
                onClick={save}
                disabled={saving}
              >
                {saving ? "saving…" : "save"}
              </button>
            </footer>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
