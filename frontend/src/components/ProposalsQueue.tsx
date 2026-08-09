"use client";

import { useState } from "react";
import {
  getProposalAlternative,
  listProposals,
  reviewProposal,
  type Proposal,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { AlternativeDisclosure } from "./AlternativeDisclosure";

/**
 * THE APPROVAL QUEUE VIEWER — where an agent's proposed commands wait for a human.
 *
 * *** REVIEWING DOES NOT RUN. *** "approve" / "reject" mark a row reviewed and stop; to actually
 * run a command the operator sends it to the executor themselves with their own gate flags. That
 * is the whole point of the queue's design (see backend/cockpit/proposals.py): there is exactly
 * one place approval-to-execute is expressed, and it is not here. This screen only reads the queue
 * and records a review decision, so the copy never says "run".
 *
 * Each row shows the gate verdict it WOULD meet (asked with approved=false — the first gate in the
 * way, not "this is allowed") and offers a ⇄ second opinion: one AI-curated alternative for the
 * proposed command.
 */
const FILTERS = ["", "pending", "approved", "rejected"] as const;

export function ProposalsQueue() {
  const [status, setStatus] = useState<string>("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [busy, setBusy] = useState<string | null>(null);
  const q = useApi(
    (signal) => listProposals({ status: status || undefined }, signal),
    [status, refreshKey],
  );

  async function review(pid: string, decision: "approved" | "rejected") {
    setBusy(pid);
    try {
      await reviewProposal(pid, decision);
      setRefreshKey((k) => k + 1);
    } catch {
      /* leave the row as-is; a refresh will resync */
    } finally {
      setBusy(null);
    }
  }

  const rows = q.data ?? [];

  return (
    <div className="hp-pq">
      <div className="hp-pq-bar">
        <div className="hp-pq-filters">
          {FILTERS.map((f) => (
            <button
              key={f || "all"}
              type="button"
              className={`hp-pq-filter${status === f ? " is-active" : ""}`}
              onClick={() => setStatus(f)}
            >
              {f || "all"}
            </button>
          ))}
        </div>
        <button
          type="button"
          className="hp-pq-refresh"
          onClick={() => setRefreshKey((k) => k + 1)}
        >
          ↻ refresh
        </button>
      </div>

      <p className="hp-pq-note">
        Reviewing records a decision — it does <b>not</b> run anything. To execute a command, send
        it to the executor yourself with your own approval flags.
      </p>

      {q.loading ? (
        <div className="hp-pq-empty">loading the queue…</div>
      ) : q.error ? (
        <div className="hp-pq-empty hp-pq-err">couldn’t load the queue — {q.error}</div>
      ) : rows.length === 0 ? (
        <div className="hp-pq-empty">
          nothing queued. An agent (via the MCP server) puts proposed commands here for you to review.
        </div>
      ) : (
        <ul className="hp-pq-list">
          {rows.map((p) => (
            <ProposalCard key={p.id} p={p} busy={busy === p.id} onReview={review} />
          ))}
        </ul>
      )}
    </div>
  );
}

function ProposalCard({
  p,
  busy,
  onReview,
}: {
  p: Proposal;
  busy: boolean;
  onReview: (pid: string, decision: "approved" | "rejected") => void;
}) {
  const g = p.gate_preview;
  return (
    <li className={`hp-pq-card is-${p.status}`}>
      <div className="hp-pq-head">
        <span className={`hp-pq-status is-${p.status}`}>{p.status}</span>
        <span className="hp-pq-source">{p.source}</span>
        <span className="hp-pq-ts">{p.created_at.slice(0, 19).replace("T", " ")}</span>
      </div>

      <pre className="hp-pq-cmd">
        <code>{p.command_line}</code>
      </pre>

      {p.rationale && (
        <p className="hp-pq-why">
          <span className="hp-pq-lead">why</span>
          {p.rationale}
        </p>
      )}
      {p.expected && (
        <p className="hp-pq-why">
          <span className="hp-pq-lead">expects</span>
          {p.expected}
        </p>
      )}

      {g.would_refuse ? (
        <p className="hp-pq-gate is-refuse">
          <span className="hp-pq-lead">gate</span>
          would be refused at <b>{g.gate}</b> — {g.reason}
          {g.dangerous_flags.length > 0 && (
            <span className="hp-pq-flags"> · {g.dangerous_flags.join(", ")}</span>
          )}
        </p>
      ) : (
        <p className="hp-pq-gate is-ok">
          <span className="hp-pq-lead">gate</span>
          passes the first check (still gated at run time)
        </p>
      )}

      <AlternativeDisclosure fetcher={() => getProposalAlternative(p.id)} />

      {p.status === "pending" ? (
        <div className="hp-pq-actions">
          <button
            type="button"
            className="hp-pq-approve"
            disabled={busy}
            onClick={() => onReview(p.id, "approved")}
            title="Mark reviewed = approved. Does NOT run it."
          >
            mark approved
          </button>
          <button
            type="button"
            className="hp-pq-reject"
            disabled={busy}
            onClick={() => onReview(p.id, "rejected")}
          >
            reject
          </button>
        </div>
      ) : (
        p.reviewer_note && (
          <p className="hp-pq-reviewed">reviewer note: {p.reviewer_note}</p>
        )
      )}
    </li>
  );
}
