"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  ApiError,
  getOllamaModels,
  setLLMConfig,
  type LLMConfig,
} from "@/lib/api";
import { useReducedMotion } from "@/lib/useReducedMotion";

type Provider = {
  value: string;
  label: string;
  defaultModel: string;
  needsKey: boolean;
  note: string;
  /**
   * Preset model ids for the picker. `ollama` has none here — its list is
   * fetched live from what's actually pulled. Every provider still gets a
   * "Custom…" escape hatch, so this list is never a hard constraint.
   */
  models?: string[];
};

const PROVIDERS: Provider[] = [
  {
    value: "ollama",
    label: "Local Ollama",
    defaultModel: "qwen3:8b",
    needsKey: false,
    note: "Free & offline. Runs on your machine — no key, nothing leaves the host.",
    // models fetched live from GET /ollama-models (what you've actually pulled).
  },
  {
    value: "openai",
    label: "OpenAI",
    defaultModel: "gpt-4o-mini",
    needsKey: true,
    note: "Uses the OpenAI Chat Completions API.",
    models: ["gpt-4o", "gpt-4o-mini", "o3-mini", "o1"],
  },
  {
    value: "anthropic",
    label: "Anthropic",
    defaultModel: "claude-opus-4-8",
    needsKey: true,
    note: "Uses the Anthropic Messages API.",
    models: ["claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5-20251001"],
  },
  {
    value: "openrouter",
    label: "OpenRouter",
    defaultModel: "openai/gpt-4o-mini",
    needsKey: true,
    note: "Routes to many models through one OpenRouter key.",
    models: [
      "openai/gpt-4o",
      "openai/gpt-4o-mini",
      "anthropic/claude-opus-4-8",
      "google/gemini-2.5-pro",
      "meta-llama/llama-3.1-70b-instruct",
    ],
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
    // The claude CLI accepts these aliases verbatim (--model); "Custom…" takes a
    // full id like claude-opus-4-8.
    models: ["opus", "sonnet", "haiku"],
  },
];

// Sentinel option value that reveals the free-text input.
const CUSTOM = "__custom__";

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
  // Models pulled locally (ollama only) + whether the free-text input is showing.
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [customModel, setCustomModel] = useState(false);

  const active = byValue(provider);

  // Preset options for the current provider: live-pulled for ollama, static
  // otherwise. Empty ollama list (Ollama down) => the picker degrades to text.
  const presetModels = provider === "ollama" ? ollamaModels : active.models ?? [];
  const hasPresets = presetModels.length > 0;
  // Custom when the user chose "Custom…" OR the current model isn't a preset
  // (e.g. a previously-saved custom id) — never drop what they already have.
  const isCustom = customModel || !presetModels.includes(model);
  const selectValue = isCustom ? CUSTOM : model;

  // Seed the form from the live config whenever the modal opens.
  useEffect(() => {
    if (!open) return;
    const p = config?.provider ?? "ollama";
    setProvider(p);
    setModel(config?.model ?? byValue(p).defaultModel);
    setApiKey("");
    setError(null);
    setSaving(false);
    setCustomModel(false);
  }, [open, config]);

  // Fetch the locally-pulled Ollama models when Ollama is the active provider.
  // Any failure => empty list => the model field falls back to free text.
  useEffect(() => {
    if (!open || provider !== "ollama") return;
    const ctrl = new AbortController();
    getOllamaModels(ctrl.signal)
      .then((r) => setOllamaModels(r.models))
      .catch(() => setOllamaModels([]));
    return () => ctrl.abort();
  }, [open, provider]);

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
    setCustomModel(false);
    setError(null);
  }

  // Model dropdown: "Custom…" reveals the free-text input (keeping the current
  // value as its starting point); any other option sets the model directly.
  function pickModel(v: string) {
    if (v === CUSTOM) {
      setCustomModel(true);
    } else {
      setCustomModel(false);
      setModel(v);
    }
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
              {hasPresets ? (
                <>
                  <select
                    id="hp-set-model"
                    className="hp-set-input hp-set-select"
                    value={selectValue}
                    onChange={(e) => pickModel(e.target.value)}
                  >
                    {presetModels.map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))}
                    <option value={CUSTOM}>Custom…</option>
                  </select>
                  {isCustom && (
                    <input
                      className="hp-set-input hp-set-custom"
                      value={model}
                      onChange={(e) => setModel(e.target.value)}
                      placeholder="model id, e.g. claude-opus-4-8"
                      spellCheck={false}
                      autoComplete="off"
                      aria-label="Custom model id"
                    />
                  )}
                </>
              ) : (
                <input
                  id="hp-set-model"
                  className="hp-set-input"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder={active.defaultModel}
                  spellCheck={false}
                  autoComplete="off"
                />
              )}
              {provider === "ollama" && !hasPresets && (
                <p className="hp-set-keynote">
                  Ollama isn’t reachable — type a model id, or start Ollama to
                  pick from your pulled models.
                </p>
              )}

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
