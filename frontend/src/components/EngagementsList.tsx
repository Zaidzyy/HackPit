"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import {
  deleteSession,
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

  useEffect(() => {
    if (fetched.data) setRows(fetched.data);
  }, [fetched.data]);

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
      </div>
    </PageShell>
  );
}
