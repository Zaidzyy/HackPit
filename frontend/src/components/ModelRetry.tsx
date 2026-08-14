"use client";

import { useEffect, useState } from "react";
import {
  getLLMConfig,
  getOllamaModels,
  setLLMConfig,
  type LLMConfig,
} from "@/lib/api";

/** claude-agent-sdk aliases — no API key (uses the machine's Claude Code login). Mirrors
 *  ModelQuickSwitch so the two inline pickers agree on what is switchable without a secret. */
const AGENT_SDK_MODELS = ["opus", "sonnet", "haiku"];

type Choice = { provider: string; model: string; label: string };

const keyOf = (p: string, m: string) => `${p}::${m}`;

/**
 * Repick-on-failure control. Rendered wherever a model-backed action failed, so the operator
 * can switch the model and re-run WITHOUT leaving the surface (previously: open settings,
 * change model, come back, retry — losing the run's place).
 *
 * It only offers a model switch when the failure is actually a MODEL failure — status 503,
 * which is what the backend maps every `llm.LLMError` to. For anything else (a 400 scope
 * reject, a dropped socket) swapping models cannot help, so it degrades to a plain retry.
 *
 * The default is opinionated: a cloud (claude-agent-sdk) model flagged by Anthropic's
 * real-time safeguards is NOT un-flagged by another cloud tier — they share the safeguard
 * layer — so the default lands on the first local Ollama model, which is not subject to it.
 * Symmetrically, a local model that failed defaults back to the cloud. It is a recommendation;
 * the dropdown still lists everything and selecting writes the global /llm-config, exactly like
 * ModelQuickSwitch, so the switch persists for the rest of the session.
 */
export function ModelRetry({
  error,
  status,
  onRetry,
  onModelChanged,
}: {
  error: string;
  status?: number;
  onRetry: () => void;
  onModelChanged?: () => void;
}) {
  const [cfg, setCfg] = useState<LLMConfig | null>(null);
  const [ollama, setOllama] = useState<string[] | null>(null);
  const [picked, setPicked] = useState<string>(""); // "provider::model", "" = use the default
  const [busy, setBusy] = useState(false);

  const isModelFailure = status === 503;

  // One-shot load of the model options when the retry UI appears. Inlined (no useCallback) so the
  // React Compiler owns memoization — a manual memo it can't preserve is what trips its lint rule.
  useEffect(() => {
    if (!isModelFailure) return;
    let alive = true;
    void (async () => {
      try {
        const c = await getLLMConfig();
        if (alive) setCfg(c);
      } catch {
        /* the badge still shows a generic label without it */
      }
      try {
        const r = await getOllamaModels();
        if (alive) setOllama(r.models);
      } catch {
        if (alive) setOllama([]);
      }
    })();
    return () => {
      alive = false;
    };
  }, [isModelFailure]);

  const choices: Choice[] = [
    ...AGENT_SDK_MODELS.map((m) => ({
      provider: "claude-agent-sdk",
      model: m,
      label: `claude-agent-sdk · ${m}`,
    })),
    ...(ollama ?? []).map((m) => ({ provider: "ollama", model: m, label: `local · ${m}` })),
  ];

  // Opinionated default: the OPPOSITE provider-kind from whatever just failed. Recomputed each
  // render (cheap) and only used until the operator picks — so it flips to Ollama the moment the
  // local list finishes loading, without an effect writing state.
  function defaultKey(): string {
    if (!cfg) return choices[0] ? keyOf(choices[0].provider, choices[0].model) : "";
    const opposite = cfg.provider === "ollama" ? "claude-agent-sdk" : "ollama";
    const want =
      choices.find((c) => c.provider === opposite) ??
      choices.find((c) => keyOf(c.provider, c.model) !== keyOf(cfg.provider, cfg.model)) ??
      choices[0];
    return want ? keyOf(want.provider, want.model) : "";
  }
  const selected = picked || defaultKey();

  async function switchAndRetry() {
    if (busy || !selected) return;
    const [provider, model] = selected.split("::");
    setBusy(true);
    try {
      await setLLMConfig({ provider, model });
      onModelChanged?.();
      onRetry();
    } catch {
      /* leave the picker up so the operator can choose another */
    } finally {
      setBusy(false);
    }
  }

  // Non-model failure: a model swap cannot fix a scope reject or a dropped socket, so offer a
  // plain retry only.
  if (!isModelFailure) {
    return (
      <div className="hp-mr" role="alert">
        <p className="hp-mr-reason">{error}</p>
        <div className="hp-mr-controls">
          <button type="button" className="hp-ck-approve" onClick={onRetry}>
            try again
          </button>
        </div>
      </div>
    );
  }

  const currentLabel = cfg ? `${cfg.provider} · ${cfg.model}` : "the current model";
  const currentIsLocal = cfg?.provider === "ollama";
  const noLocal = ollama !== null && ollama.length === 0;

  return (
    <div className="hp-mr" role="alert">
      <p className="hp-mr-reason">
        <span className="hp-mr-tag">model call failed</span> {error}
      </p>
      <p className="hp-mr-hint">
        {currentIsLocal ? (
          <>
            <b>{currentLabel}</b> is a <b>small local model</b> — it likely returned malformed
            output (bad JSON) or was unreachable, not a safeguard. A more capable model (a cloud
            tier, or a larger local one) is more reliable for the strict JSON the loop needs.
          </>
        ) : (
          <>
            <b>{currentLabel}</b> was flagged or unreachable. A safeguard on a cloud model is not
            lifted by another cloud tier — a <b>local</b> model is not subject to it.
          </>
        )}
      </p>

      {noLocal ? (
        <p className="hp-mr-hint">
          No local model pulled — <code className="hp-code">ollama pull llama3.1</code> gives you
          a safeguard-free fallback. You can still retry the same model below.
        </p>
      ) : (
        <label className="hp-mr-field">
          <span>retry on</span>
          <select
            className="hp-mr-select"
            value={selected}
            onChange={(e) => setPicked(e.target.value)}
            disabled={busy || ollama === null}
          >
            {ollama === null ? (
              <option value="">loading…</option>
            ) : (
              choices.map((c) => (
                <option key={keyOf(c.provider, c.model)} value={keyOf(c.provider, c.model)}>
                  {c.label}
                </option>
              ))
            )}
          </select>
        </label>
      )}

      <div className="hp-mr-controls">
        {!noLocal && (
          <button
            type="button"
            className="hp-ck-approve"
            onClick={switchAndRetry}
            disabled={busy || !selected || ollama === null}
          >
            {busy ? "switching…" : "switch & retry"}
          </button>
        )}
        <button type="button" className="hp-mr-again" onClick={onRetry} disabled={busy}>
          try again — same model
        </button>
      </div>
    </div>
  );
}
