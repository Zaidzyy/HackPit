"use client";

import type { LLMConfig } from "@/lib/api";

/**
 * The "composed by {model} · {provider} ⚙" affordance shown near a compose bar.
 * Shared by the attack-path screen and the cockpit so the two never drift: both
 * render this exact badge and read the same /llm-config (the gear opens the
 * shared LLMSettingsModal, owned by the caller). Presentational — the caller
 * loads the config and owns the modal open-state.
 */
export function ModelBadge({
  config,
  onOpenSettings,
}: {
  config: LLMConfig | null;
  onOpenSettings: () => void;
}) {
  const providerLabel =
    config?.provider === "ollama" ? "local" : config?.provider;

  return (
    <div className="hp-ap-hint">
      <span className="hp-ap-hint-dot" />
      {config ? (
        <>
          composed by <b>{config.model}</b>
          <span className="hp-ap-local"> · {providerLabel}</span>{" "}
          <button
            type="button"
            className="hp-ap-gear hp-ap-gear-inline"
            aria-label="LLM settings"
            onClick={onOpenSettings}
          >
            ⚙
          </button>
        </>
      ) : (
        <>knowledge-base grounded · local &amp; offline by default</>
      )}
    </div>
  );
}
