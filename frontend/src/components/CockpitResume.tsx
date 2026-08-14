"use client";

import { useState } from "react";
import {
  deleteSession,
  getSession,
  listSessions,
  type AttackPath,
  type EngagementPath,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";

function relTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

/**
 * EngagementPath (what a saved session stores) → the AttackPath the cockpit map + exec section
 * render. `EngagementStep` extends `AttackStep`, so `phases` carry through unchanged; the only
 * required field the stored path lacks is `box_writeup` (a saved session is a *composed* path,
 * never a writeup one), so it is set to null. Every other AttackPath field is optional.
 */
function toAttackPath(ep: EngagementPath): AttackPath {
  return {
    goal: ep.goal,
    target_type: ep.target_type,
    target: ep.target ?? null,
    phases: ep.phases,
    box_writeup: null,
    model_used: ep.model_used,
    provider: ep.provider,
  };
}

/**
 * "Resume an engagement" — a peer to plotting on the cockpit entry screen.
 *
 * The exec section (lab/engagement toggle, the loop, the `exit engagement` button) is gated on
 * `path` being set, and the ONLY thing that set `path` was compose() (plotting). So a saved
 * engagement was unreachable in the cockpit — you had to re-plot just to get back to it. This
 * loads a saved session's stored path back in (setPath + setSessionId via `onResume`), lighting
 * up the SAME exec section with no re-plot and no new engine. A per-row ✕ removes a saved session
 * without entering the exec surface at all.
 *
 * Note: "engagement" here is the saved attack-path SESSION (what /engagements lists), not the
 * real-target sandbox that the red `exit engagement` button tears down — those stay distinct.
 */
export function CockpitResume({
  onResume,
}: {
  onResume: (path: AttackPath, sessionId: string) => void;
}) {
  const fetched = useApi(listSessions, []);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const rows = (fetched.data ?? [])
    .filter((s) => !hidden.has(s.id))
    .slice()
    .sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1))
    .slice(0, 8);

  // Stay invisible until we know, and when there is nothing to resume — the entry screen should
  // not grow an empty panel.
  if (rows.length === 0) return null;

  function resume(id: string) {
    if (busy) return;
    setBusy(id);
    setErr(null);
    getSession(id)
      .then((s) => onResume(toAttackPath(s.path), s.id))
      .catch(() => setErr("Couldn’t load that engagement."))
      .finally(() => setBusy(null));
  }

  function remove(id: string) {
    if (busy) return;
    setBusy(id);
    setErr(null);
    deleteSession(id)
      .then(() => setHidden((h) => new Set(h).add(id)))
      .catch(() => setErr("Couldn’t remove that engagement."))
      .finally(() => setBusy(null));
  }

  return (
    <div className="hp-cr">
      <div className="hp-cr-head">
        <span className="hp-cr-title">Resume an engagement</span>
        <span className="hp-cr-sub">— or plot a new one below</span>
      </div>
      <ul className="hp-cr-list">
        {rows.map((s) => {
          const done = s.total > 0 && s.checked === s.total;
          return (
            <li className="hp-cr-row" key={s.id}>
              <button
                type="button"
                className="hp-cr-resume"
                onClick={() => resume(s.id)}
                disabled={busy === s.id}
                title="Load this engagement back into the cockpit — no re-plot"
              >
                <span className="hp-cr-label">{s.label}</span>
                <span className="hp-cr-meta">
                  {s.target_type && <span className="hp-cr-chip">{s.target_type}</span>}
                  <span className="hp-cr-count">
                    {s.checked}/{s.total}
                    {done ? " ✓" : ""}
                  </span>
                  <span className="hp-cr-time">updated {relTime(s.updated_at)}</span>
                </span>
              </button>
              <button
                type="button"
                className="hp-cr-del"
                onClick={() => remove(s.id)}
                disabled={busy === s.id}
                aria-label={`Remove ${s.label}`}
                title="Remove this saved engagement"
              >
                {busy === s.id ? "…" : "✕"}
              </button>
            </li>
          );
        })}
      </ul>
      {err && <p className="hp-cr-err">{err}</p>}
    </div>
  );
}
