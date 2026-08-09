"use client";

import type { HomeRail } from "@/lib/api";
import { ModelQuickSwitch } from "./ModelQuickSwitch";

type Cell = {
  key: string;
  /** up | down | warn | unknown — drives the dot colour only. */
  tone: "up" | "down" | "warn" | "unknown";
  label: string;
  value: string;
  sub?: string;
  /** Highlights the cell (used for an active engagement). */
  accent?: boolean;
};

/**
 * The launcher status rail.
 *
 * WHY IT EXISTS: every execution surface shells out to `docker exec` and refuses
 * with "bring the stack up" when the container is down — but you only discovered
 * that by clicking into a surface and reading an error. The rail answers "why is
 * that refusing?" before you click.
 *
 * It shows STATUS ONLY. The backend sends the LLM model *name* and the Windows
 * profile's *display name*; no secret is in this payload by construction
 * (backend/test_home_summary.py asserts that against the real stores).
 */
export function StatusRail({
  rail,
  loading,
  error,
  onOpenSettings,
  onModelChanged,
}: {
  rail: HomeRail | null;
  loading: boolean;
  error: string | null;
  /** Opens the full LLM settings modal (owned by the caller) — for keyed providers. */
  onOpenSettings?: () => void;
  /** Called after an inline no-key model switch, so the caller can refresh the rail. */
  onModelChanged?: () => void;
}) {
  if (error) {
    return (
      <div className="hp-rail hp-rail-msg" role="status">
        <span className="hp-dot hp-dot-down" aria-hidden />
        backend unreachable — {error}
      </div>
    );
  }

  if (loading || !rail) {
    return (
      <div className="hp-rail hp-rail-msg" role="status">
        <span className="hp-dot hp-dot-unknown" aria-hidden />
        checking stack, model and targets…
      </div>
    );
  }

  // `null` means the probe could not determine the answer (docker absent, timed
  // out). That is NOT the same as "down", and showing it as down would send you
  // chasing a container problem you don't have.
  const stackTone: Cell["tone"] =
    rail.sandbox_up === null ? "unknown" : rail.sandbox_up ? "up" : "down";
  const stackValue =
    rail.sandbox_up === null ? "unknown" : rail.sandbox_up ? "up" : "down";

  const cells: Cell[] = [
    {
      key: "stack",
      tone: stackTone,
      label: "sandbox stack",
      value: stackValue,
      sub: rail.engage_sandbox_up ? "· engage up" : undefined,
    },
    {
      key: "llm",
      tone: rail.llm_model ? "up" : "unknown",
      label: rail.llm_provider || "llm",
      value: rail.llm_model || "not configured",
    },
    {
      key: "winrm",
      tone: rail.windows_profile ? "warn" : "unknown",
      label: "winrm",
      value: rail.windows_profile || "no target",
      sub: rail.windows_profile ? "· idle" : undefined,
    },
    {
      key: "engagement",
      tone: rail.engagement_id ? "up" : "unknown",
      label: "engagement",
      value: rail.engagement_id || "none active",
      sub: rail.engagement_target ? `· ${rail.engagement_target}` : undefined,
      accent: !!rail.engagement_id,
    },
  ];

  return (
    <div className="hp-rail">
      {cells.map((c) =>
        c.key === "llm" && onOpenSettings ? (
          <ModelQuickSwitch
            key="llm"
            provider={rail.llm_provider}
            model={rail.llm_model}
            tone={c.tone}
            onOpenSettings={onOpenSettings}
            onModelChanged={onModelChanged}
          />
        ) : (
          <div
            key={c.key}
            className={`hp-st${c.accent ? " hp-st-on" : ""}`}
            title={`${c.label}: ${c.value}`}
          >
            <span className={`hp-dot hp-dot-${c.tone}`} aria-hidden />
            <span>
              {c.label}&nbsp; <b>{c.value}</b>
              {c.sub ? <span className="hp-sub"> {c.sub}</span> : null}
            </span>
          </div>
        )
      )}
    </div>
  );
}
