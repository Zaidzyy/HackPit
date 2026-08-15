"use client";

import { useCallback, useEffect, useState, type CSSProperties } from "react";
import {
  getAutorun,
  getAutorunAudit,
  getEgress,
  getWatch,
  setAutonomyMode,
  setAutorun,
  setEgress,
  type AutonomyMode,
  type AutorunAuditEntry,
  type AutorunStatus,
  type EgressConfig,
  type EngagementRecord,
  type WatchAlert,
} from "@/lib/api";

/**
 * AUTONOMY panel — the operator's controls for the auto-runner (modes 2/3), the scheduler, egress
 * and continuous hunting. Self-contained so the big engagement component stays untouched.
 *
 * The safety story it makes visible: TWO switches guard autonomous firing — this engagement's mode
 * (manual/assisted/full) AND the scheduler daemon toggle — and BOTH must be on before anything
 * runs without a human. Manual is the default; nothing here fires anything by rendering.
 */

const MODES: { mode: AutonomyMode; label: string; blurb: string }[] = [
  { mode: "manual", label: "Manual", blurb: "You approve every command. Today's behaviour." },
  { mode: "assisted", label: "Assisted", blurb: "Passive/recon auto-fires; exploitation is queued for you." },
  { mode: "full", label: "Full auto", blurb: "Everything auto-fires, bounded by RoE + scope + budget." },
];

const MODE_COLOR: Record<AutonomyMode, string> = {
  manual: "#9aa",
  assisted: "#e0a92b",
  full: "#e0632b",
};

// Matches `.hp-ck-field input` in globals.css. Applied inline because those classes are WRAPPERS
// (flex column + margin) whose styling targets a child `input`, not the element itself — putting
// the class on the input/textarea directly mis-lays it out (this is what raised the interval number).
const FIELD: CSSProperties = {
  fontFamily: "var(--font-jetbrains-mono), monospace",
  fontSize: 13,
  color: "var(--white)",
  background: "#0a0b0b",
  border: "1px solid var(--border-2)",
  borderRadius: 7,
  padding: "8px 10px",
  outline: "none",
};

export function CockpitAutonomyPanel({
  active,
  onModeChanged,
}: {
  active: EngagementRecord;
  onModeChanged?: (mode: AutonomyMode) => void;
}) {
  const eid = active.engagement_id;

  const [mode, setMode] = useState<AutonomyMode>(active.autonomy_mode ?? "manual");
  const [busyMode, setBusyMode] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const [autorun, setAutorunState] = useState<AutorunStatus | null>(null);
  const [intervalText, setIntervalText] = useState("60");

  const [egress, setEgressState] = useState<EgressConfig | null>(null);
  const [poolText, setPoolText] = useState("");
  const [identifyText, setIdentifyText] = useState("");
  const [egressBusy, setEgressBusy] = useState(false);

  const [alerts, setAlerts] = useState<WatchAlert[]>([]);
  const [feed, setFeed] = useState<AutorunAuditEntry[]>([]);

  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [ar, eg, w, au] = await Promise.all([
          getAutorun(signal).catch(() => null),
          getEgress(eid, signal).catch(() => null),
          getWatch(eid, 20, signal).catch(() => null),
          getAutorunAudit(eid, 20, signal).catch(() => null),
        ]);
        if (ar) {
          setAutorunState(ar);
          setIntervalText(String(ar.interval));
        }
        if (eg) setEgressState(eg);
        if (w) setAlerts(w.alerts);
        if (au) setFeed(au.entries);
      } catch {
        /* a status hiccup is not worth an error banner — the controls still work */
      }
    },
    [eid]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect -- deliberate status auto-load for the active engagement
    void load(ctrl.signal);
    return () => ctrl.abort();
  }, [load]);

  const chooseMode = useCallback(
    (next: AutonomyMode) => {
      if (next === mode || busyMode) return;
      setBusyMode(true);
      setErr(null);
      setAutonomyMode(eid, next)
        .then((r) => {
          setMode(r.autonomy_mode);
          onModeChanged?.(r.autonomy_mode);
        })
        .catch((e) => setErr(e?.message ?? "could not set mode"))
        .finally(() => setBusyMode(false));
    },
    [eid, mode, busyMode, onModeChanged]
  );

  const toggleScheduler = useCallback(
    (enabled: boolean) => {
      const secs = Math.max(1, parseInt(intervalText, 10) || 60);
      setAutorun(enabled, secs)
        .then(setAutorunState)
        .catch((e) => setErr(e?.message ?? "could not toggle the scheduler"));
    },
    [intervalText]
  );

  const saveEgress = useCallback(() => {
    setEgressBusy(true);
    setErr(null);
    const pool = poolText
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    setEgress(eid, pool, identifyText.trim())
      .then((r) => {
        setEgressState(r);
        setPoolText(""); // WRITE-ONLY: never echo the URLs back into the field
      })
      .catch((e) => setErr(e?.message ?? "could not save egress config"))
      .finally(() => setEgressBusy(false));
  }, [eid, poolText, identifyText]);

  const schedulerOn = autorun?.enabled ?? false;
  const firesAutonomously = mode !== "manual" && schedulerOn;

  return (
    <section className="hp-eng-scope" aria-label="Autonomy">
      {/* ---- mode: the FIRST switch ------------------------------------------------------ */}
      <div className="hp-eng-scope-row">
        <span className="hp-eng-scope-key">autonomy</span>
        <span className="hp-eng-scope-vals" style={{ gap: 8, flexWrap: "wrap" }}>
          {MODES.map((m) => {
            const on = m.mode === mode;
            return (
              <button
                key={m.mode}
                type="button"
                className="hp-ck-report-btn"
                onClick={() => chooseMode(m.mode)}
                disabled={busyMode}
                title={m.blurb}
                style={{
                  borderColor: on ? MODE_COLOR[m.mode] : undefined,
                  color: on ? MODE_COLOR[m.mode] : undefined,
                  fontWeight: on ? 700 : 400,
                  boxShadow: on ? `0 0 0 1px ${MODE_COLOR[m.mode]}` : undefined,
                }}
              >
                {on ? "● " : ""}
                {m.label}
              </button>
            );
          })}
        </span>
      </div>
      <div className="hp-eng-scope-row">
        <span className="hp-eng-scope-key" />
        <span className="hp-ck-hint">{MODES.find((m) => m.mode === mode)?.blurb}</span>
      </div>

      {/* ---- scheduler: the SECOND switch (both must be on to fire) ---------------------- */}
      <div className="hp-eng-scope-row">
        <span className="hp-eng-scope-key">scheduler</span>
        <span className="hp-eng-scope-vals" style={{ gap: 8, alignItems: "center" }}>
          <button
            type="button"
            className="hp-ck-report-btn"
            onClick={() => toggleScheduler(!schedulerOn)}
            style={{
              borderColor: schedulerOn ? "#e0632b" : undefined,
              color: schedulerOn ? "#e0632b" : undefined,
              fontWeight: schedulerOn ? 700 : 400,
            }}
          >
            {schedulerOn ? "● daemon ON — click to stop (kill-switch)" : "daemon OFF — click to enable"}
          </button>
          <label className="hp-ck-hint" style={{ display: "inline-flex", gap: 4, alignItems: "center" }}>
            every
            <input
              value={intervalText}
              onChange={(e) => setIntervalText(e.target.value)}
              onBlur={() => {
                if (schedulerOn) toggleScheduler(true);
              }}
              style={{ ...FIELD, width: 64, textAlign: "center", padding: "5px 8px" }}
              inputMode="numeric"
              aria-label="scheduler interval seconds"
            />
            s{autorun ? ` (min ${autorun.min_interval})` : ""}
          </label>
        </span>
      </div>
      <div className="hp-eng-scope-row">
        <span className="hp-eng-scope-key" />
        <span
          className="hp-ck-hint"
          style={{ color: firesAutonomously ? "#e0632b" : undefined, fontWeight: firesAutonomously ? 700 : 400 }}
        >
          {firesAutonomously
            ? `⚠ FIRING AUTONOMOUSLY — this engagement is ${mode} and the scheduler is on.`
            : "Both switches must be on for anything to run without your approval. Currently one is off."}
        </span>
      </div>

      {/* ---- egress: rotating source IP + identify header -------------------------------- */}
      <div className="hp-eng-scope-row">
        <span className="hp-eng-scope-key">egress</span>
        <span className="hp-eng-scope-vals" style={{ flexDirection: "column", alignItems: "stretch", gap: 6 }}>
          <span className="hp-ck-hint">
            {egress
              ? `${egress.egress_pool_size} proxy IP(s) held${
                  egress.egress_identify_name ? ` · identify: ${egress.egress_identify_name}` : ""
                }${egress.banned_count ? ` · ${egress.banned_count} benched` : ""}`
              : "no egress pool configured — runs go direct from the sandbox IP"}
          </span>
          <textarea
            placeholder={"one proxy URL per line (write-only)\nhttp://user:pass@host:8080\nsocks5://1.2.3.4:1080"}
            value={poolText}
            onChange={(e) => setPoolText(e.target.value)}
            rows={3}
            style={{ ...FIELD, width: "100%", resize: "vertical" }}
          />
          <input
            placeholder="identify header, e.g. X-Bug-Bounty: your-handle"
            value={identifyText}
            onChange={(e) => setIdentifyText(e.target.value)}
            style={{ ...FIELD, width: "100%" }}
          />
          <button type="button" className="hp-ck-report-btn" onClick={saveEgress} disabled={egressBusy}>
            {egressBusy ? "saving..." : "save egress pool + identify header (write-only)"}
          </button>
        </span>
      </div>

      {/* ---- continuous hunting: new-asset alerts --------------------------------------- */}
      {alerts.length > 0 && (
        <div className="hp-eng-scope-row">
          <span className="hp-eng-scope-key">new assets</span>
          <span className="hp-eng-scope-vals" style={{ flexDirection: "column", alignItems: "stretch", gap: 4 }}>
            {alerts.slice(0, 6).map((a, i) => (
              <span key={`${a.at}-${i}`} className="hp-ck-hint">
                <b style={{ color: "#e0a92b" }}>{new Date(a.at).toLocaleTimeString()}</b>{" "}
                {Object.entries(a.new_assets)
                  .map(([cat, items]) => `${items.length} ${cat}`)
                  .join(", ")}
              </span>
            ))}
          </span>
        </div>
      )}

      {/* ---- the auto-runner activity feed (what it fired / queued) ---------------------- */}
      {feed.length > 0 && (
        <div className="hp-eng-scope-row">
          <span className="hp-eng-scope-key">activity</span>
          <span className="hp-eng-scope-vals" style={{ flexDirection: "column", alignItems: "stretch", gap: 2 }}>
            {feed.slice(0, 8).map((e, i) => (
              <span key={`${e.at}-${i}`} className="hp-ck-line" style={{ fontSize: 12 }}>
                <span
                  style={{
                    color:
                      e.action === "fire" ? "#e0632b" : e.action === "queue" ? "#e0a92b" : "#9aa",
                    fontWeight: 700,
                  }}
                >
                  {e.action}
                </span>{" "}
                <span style={{ opacity: 0.8 }}>{e.tier}</span>{" "}
                {e.surface ?? e.command ?? e.kind}
                {e.outcome === "error" ? " ✕" : ""}
              </span>
            ))}
          </span>
        </div>
      )}

      {err && <div className="hp-eng-warn">{err}</div>}
    </section>
  );
}
