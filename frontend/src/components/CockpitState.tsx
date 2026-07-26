"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ApiError,
  getSessionState,
  seedSessionTasks,
  type SessionState,
  type StateCredential,
  type StateTask,
} from "@/lib/api";

/**
 * ENGAGEMENT STATE — what HackPit actually knows, and the live plan.
 *
 * Before the state model, every result was a text blob and the only durable record of a run
 * was its stdout. This panel renders the structured picture the planner now reasons over:
 * hosts and their services, reachable endpoints, captured credentials, established findings,
 * and the Pentest Task Tree.
 *
 * The task tree in particular belongs on screen rather than only inside a prompt. It is the
 * live plan — what is done, what is ruled out, what the results have newly opened up — and a
 * plan the operator cannot see is not a plan they can steer.
 *
 * Read-only. Nothing here executes, approves or modifies anything; the one write is seeding
 * the tree from the composed plan, which is idempotent server-side.
 *
 * Rendered with `key={sessionId}` by the parent so a new engagement gets a fresh instance.
 * `refreshToken` is bumped after each run so the state re-pulls.
 */

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function credLabel(c: StateCredential): string {
  return c.domain ? `${c.principal}@${c.domain}` : c.principal;
}

/** Mask a secret so a shoulder-surfer or a screenshot does not leak it. The real value is
 *  one click away — this is a display default, not a security control: the value is already
 *  in the run record and the operator needs it to drive tools. */
function mask(secret: string): string {
  if (!secret) return "—";
  if (secret.length <= 8) return "•".repeat(secret.length);
  return `${secret.slice(0, 4)}${"•".repeat(Math.min(secret.length - 8, 24))}${secret.slice(-4)}`;
}

export function CockpitState({
  sessionId,
  refreshToken,
}: {
  sessionId: string;
  refreshToken: number;
}) {
  const [state, setState] = useState<SessionState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Which credential secrets the operator has explicitly revealed, by row index.
  const [revealed, setRevealed] = useState<Set<number>>(new Set());

  const load = useCallback(
    (signal?: AbortSignal) => {
      getSessionState(sessionId, signal)
        .then((s) => {
          if (signal?.aborted) return;
          setState(s);
          setError(null);
        })
        .catch((err: unknown) => {
          if (signal?.aborted) return;
          setError(err instanceof ApiError ? err.message : "Could not load engagement state.");
        });
    },
    [sessionId]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    load(ctrl.signal);
    return () => ctrl.abort();
  }, [load, refreshToken]);

  const seed = useCallback(() => {
    setBusy(true);
    seedSessionTasks(sessionId)
      .then(() => load())
      .catch((err: unknown) =>
        setError(err instanceof ApiError ? err.message : "Could not seed the task tree.")
      )
      .finally(() => setBusy(false));
  }, [sessionId, load]);

  const findings = useMemo(() => {
    const list = state?.findings ?? [];
    return [...list].sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
        a.title.localeCompare(b.title)
    );
  }, [state]);

  // Services grouped under the host they belong to — the shape an operator reads.
  const hostRows = useMemo(() => {
    if (!state) return [];
    const byHost = new Map<string, typeof state.services>();
    for (const svc of state.services) {
      const key = svc.address.toLowerCase();
      byHost.set(key, [...(byHost.get(key) ?? []), svc]);
    }
    const addresses = state.hosts.map((h) => h.address);
    for (const addr of byHost.keys()) {
      if (!addresses.some((a) => a.toLowerCase() === addr)) addresses.push(addr);
    }
    return addresses.map((address) => ({
      address,
      host: state.hosts.find((h) => h.address.toLowerCase() === address.toLowerCase()) ?? null,
      services: byHost.get(address.toLowerCase()) ?? [],
    }));
  }, [state]);

  if (error && !state) {
    return <p className="hp-cs-empty">{error}</p>;
  }
  if (!state) {
    return <p className="hp-cs-empty">Loading engagement state…</p>;
  }

  const { counts, task_progress: progress } = state;
  const nothingYet =
    counts.hosts + counts.services + counts.endpoints + counts.credentials + counts.findings === 0;

  return (
    <section className="hp-cs">
      <header className="hp-cs-head">
        <h3 className="hp-cs-title">Engagement state</h3>
        <p className="hp-cs-sub">
          Built automatically from every run — this is what the planner reasons over instead
          of re-reading raw output.
        </p>
      </header>

      <div className="hp-cs-counts">
        {(
          [
            ["hosts", counts.hosts],
            ["services", counts.services],
            ["endpoints", counts.endpoints],
            ["credentials", counts.credentials],
            ["findings", counts.findings],
          ] as const
        ).map(([label, n]) => (
          <div key={label} className={`hp-cs-count${n > 0 ? " hp-on" : ""}`}>
            <b>{n}</b>
            <span>{label}</span>
          </div>
        ))}
      </div>

      {nothingYet && (
        <p className="hp-cs-empty">
          Nothing captured yet. State fills in as commands run — an <code>nmap -oA</code>{" "}
          writes its XML into the engagement&apos;s loot directory and its hosts and services
          land here; <code>httpx</code>, <code>nuclei</code> and <code>secretsdump</code> are
          read straight from their output.
        </p>
      )}

      {/* --- task tree: the live plan ------------------------------------------- */}
      <div className="hp-cs-block">
        <div className="hp-cs-blockhead">
          <h4>
            Task tree
            {progress.total > 0 && (
              <span className="hp-cs-progress">
                {progress.done} done · {progress.todo} to-do
                {progress.na > 0 && ` · ${progress.na} n/a`}
              </span>
            )}
          </h4>
          {state.tasks.length === 0 && (
            <button type="button" className="hp-cs-seed" onClick={seed} disabled={busy}>
              {busy ? "seeding…" : "seed from plan"}
            </button>
          )}
        </div>
        {state.tasks.length === 0 ? (
          <p className="hp-cs-empty">
            No tasks yet. Seed the tree from the composed plan and the agent keeps it current
            as results arrive — marking steps done, ruling out dead branches, and adding
            sub-tasks for what the results open up.
          </p>
        ) : (
          <ul className="hp-cs-tasks">
            {state.tasks.map((t: StateTask) => (
              <li
                key={t.task_id}
                className={`hp-cs-task hp-cs-task-${t.status.replace("/", "")}`}
                style={{ paddingLeft: `${(t.depth - 1) * 18}px` }}
              >
                <span className="hp-cs-taskmark" aria-hidden>
                  {t.status === "done" ? "✓" : t.status === "n/a" ? "–" : "○"}
                </span>
                <span className="hp-cs-taskid">{t.task_id}</span>
                <span className="hp-cs-tasktitle">{t.title}</span>
                {t.why && <span className="hp-cs-taskwhy">{t.why}</span>}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* --- hosts + services ---------------------------------------------------- */}
      {hostRows.length > 0 && (
        <div className="hp-cs-block">
          <h4>Hosts and services</h4>
          <ul className="hp-cs-hosts">
            {hostRows.map((row) => (
              <li key={row.address}>
                <div className="hp-cs-hostline">
                  <b>{row.address}</b>
                  {row.host?.hostname && row.host.hostname !== row.address && (
                    <span className="hp-cs-hostname">{row.host.hostname}</span>
                  )}
                  {row.host?.os && <span className="hp-cs-os">{row.host.os}</span>}
                </div>
                {row.services.length > 0 ? (
                  <div className="hp-cs-svcs">
                    {row.services.map((s) => (
                      <span key={`${s.port}/${s.proto}`} className="hp-cs-svc">
                        <b>
                          {s.port}/{s.proto}
                        </b>
                        {s.name && ` ${s.name}`}
                        {(s.product || s.version) && (
                          <i>{` ${[s.product, s.version].filter(Boolean).join(" ")}`}</i>
                        )}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="hp-cs-svcs hp-cs-dim">no services recorded yet</div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* --- endpoints ----------------------------------------------------------- */}
      {state.endpoints.length > 0 && (
        <div className="hp-cs-block">
          <h4>HTTP endpoints</h4>
          <ul className="hp-cs-eps">
            {state.endpoints.map((e) => (
              <li key={`${e.method} ${e.url}`}>
                {e.status !== null && (
                  <span className={`hp-cs-status hp-cs-s${Math.floor(e.status / 100)}`}>
                    {e.status}
                  </span>
                )}
                <code>{e.url}</code>
                {e.title && <span className="hp-cs-eptitle">{e.title}</span>}
                {e.tech && <span className="hp-cs-eptech">{e.tech}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* --- credentials --------------------------------------------------------- */}
      {state.credentials.length > 0 && (
        <div className="hp-cs-block">
          <h4>Credentials</h4>
          <ul className="hp-cs-creds">
            {state.credentials.map((c, i) => (
              <li key={`${c.kind}:${credLabel(c)}`}>
                <span className="hp-cs-credkind">{c.kind}</span>
                <b>{credLabel(c)}</b>
                <code className="hp-cs-secret">
                  {revealed.has(i) ? c.secret || "—" : mask(c.secret)}
                </code>
                {c.secret && (
                  <button
                    type="button"
                    className="hp-cs-reveal"
                    onClick={() =>
                      setRevealed((prev) => {
                        const next = new Set(prev);
                        if (next.has(i)) next.delete(i);
                        else next.add(i);
                        return next;
                      })
                    }
                  >
                    {revealed.has(i) ? "hide" : "reveal"}
                  </button>
                )}
                <span
                  className={`hp-cs-credval${
                    c.validated === true ? " hp-ok" : c.validated === false ? " hp-bad" : ""
                  }`}
                >
                  {c.validated === true
                    ? "validated"
                    : c.validated === false
                      ? "failed"
                      : "untested"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* --- findings ------------------------------------------------------------ */}
      {findings.length > 0 && (
        <div className="hp-cs-block">
          <h4>Findings</h4>
          <ul className="hp-cs-findings">
            {findings.map((f) => (
              <li key={f.fingerprint}>
                <span className={`hp-cs-sev hp-cs-sev-${f.severity}`}>{f.severity}</span>
                <b>{f.title}</b>
                {f.target && <code className="hp-cs-ftarget">{f.target}</code>}
                {f.reference && <span className="hp-cs-fref">{f.reference}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
