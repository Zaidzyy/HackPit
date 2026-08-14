"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { FindingPipelinePanel } from "./FindingPipelinePanel";
import {
  deleteSession,
  exitEngagement,
  getEngagementStatus,
  listSessions,
  type SessionSummary,
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

/** The saved-engagements list: progress, open, delete. */
export function EngagementsList() {
  const fetched = useApi(listSessions, []);
  const [rows, setRows] = useState<SessionSummary[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // session_id -> engagement_id for engagements that are LIVE right now, so a row can offer a
  // non-destructive "stop" (end real-target mode, keep the saved path) instead of only delete.
  const [activeBySession, setActiveBySession] = useState<Record<string, string>>({});

  useEffect(() => {
    if (fetched.data) setRows(fetched.data);
  }, [fetched.data]);

  // Which saved engagement (if any) is currently live — one engagement is active at a time.
  useEffect(() => {
    const ctrl = new AbortController();
    getEngagementStatus(ctrl.signal)
      .then((st) => {
        const map: Record<string, string> = {};
        for (const e of st.active) {
          if (e.session_id) map[e.session_id] = e.engagement_id;
        }
        setActiveBySession(map);
      })
      .catch(() => {
        /* no status → no stop buttons; delete still works */
      });
    return () => ctrl.abort();
  }, []);

  // Stop = leave real-target mode for this engagement. Keeps the saved session (path, runs,
  // findings) — the row stays, it just loses its "live" state and its stop button.
  const stop = useCallback((engagementId: string, sessionId: string) => {
    setBusy(sessionId);
    exitEngagement(engagementId)
      .then(() =>
        setActiveBySession((prev) => {
          const next = { ...prev };
          delete next[sessionId];
          return next;
        })
      )
      .catch(() => {
        /* leave it live; the user can retry */
      })
      .finally(() => setBusy(null));
  }, []);

  const remove = useCallback((id: string) => {
    setBusy(id);
    deleteSession(id)
      .then(() => setRows((prev) => prev?.filter((r) => r.id !== id) ?? null))
      .catch(() => {
        /* leave the row; the user can retry */
      })
      .finally(() => setBusy(null));
  }, []);

  return (
    <PageShell
      crumbs={[{ label: "home", href: "/" }, { label: "engagements" }]}
    >
      <div className="hp-engs">
        <header className="hp-engs-head">
          <h1 className="hp-engs-title">Your engagements</h1>
          <p className="hp-engs-sub">
            Saved attack paths you&apos;re working through. Progress and pasted
            results persist locally.
          </p>
          <Link href="/attack-path" className="hp-engs-new">
            + compose a new path
          </Link>
        </header>

        {fetched.loading && !rows && (
          <p className="hp-note">loading engagements…</p>
        )}

        {fetched.error && !rows && (
          <div className="hp-error-box">
            <p>{fetched.error}</p>
          </div>
        )}

        {rows && rows.length === 0 && (
          <div className="hp-engs-empty">
            <p>No engagements yet.</p>
            <p className="hp-engs-empty-sub">
              Compose a guided attack path, then hit{" "}
              <b>Start engagement</b> to save it here.
            </p>
            <Link href="/attack-path" className="hp-ap-start hp-engs-empty-cta">
              Compose an attack path →
            </Link>
          </div>
        )}

        {rows && rows.length > 0 && (
          <ul className="hp-engs-list">
            {rows.map((s) => {
              const pct = s.total > 0 ? Math.round((s.checked / s.total) * 100) : 0;
              const done = s.total > 0 && s.checked === s.total;
              return (
                <li className="hp-engs-row" key={s.id}>
                  <Link href={`/engagement/${s.id}`} className="hp-engs-open">
                    <div className="hp-engs-row-main">
                      <span className="hp-engs-row-label">{s.label}</span>
                      <span className="hp-engs-row-meta">
                        {s.target_type ? (
                          <span className="hp-chip hp-chip-dim">
                            {s.target_type}
                          </span>
                        ) : null}
                        {activeBySession[s.id] ? (
                          <span className="hp-chip hp-engs-live">● live</span>
                        ) : null}
                        <span className="hp-engs-row-time">
                          updated {relTime(s.updated_at)}
                        </span>
                      </span>
                    </div>
                    <div className="hp-engs-row-prog">
                      <div className="hp-eng-bar hp-engs-row-bar">
                        <div
                          className="hp-eng-bar-fill"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="hp-engs-row-count">
                        {s.checked}/{s.total}
                        {done ? " ✓" : ""}
                      </span>
                    </div>
                  </Link>
                  {activeBySession[s.id] ? (
                    <button
                      type="button"
                      className="hp-engs-stop"
                      onClick={() => stop(activeBySession[s.id], s.id)}
                      disabled={busy === s.id}
                      aria-label={`Stop the live engagement ${s.label} (keeps it saved)`}
                    >
                      {busy === s.id ? "…" : "stop"}
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="hp-engs-del"
                    onClick={() => remove(s.id)}
                    disabled={busy === s.id}
                    aria-label={`Delete ${s.label}`}
                  >
                    {busy === s.id ? "…" : "delete"}
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        <FindingPipelinePanel />
      </div>
    </PageShell>
  );
}
