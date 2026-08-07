"use client";

import { useCallback, useEffect, useState } from "react";
import {
  addObjective,
  approveGovernanceDoc,
  deleteObjective,
  draftGovernanceDoc,
  getGovernance,
  saveGovernanceDoc,
  seedOpplan,
  updateObjective,
  type GovDoc,
  type GovDocType,
  type GovernancePackage,
  type Objective,
} from "@/lib/api";

/**
 * Formal engagement governance on /engagement/[id]: RoE / ConOps / Deconfliction / OPPLAN
 * tabs, an objectives board with a status state machine, and a MITRE ATT&CK coverage view.
 *
 * Everything here is authored + human-approved documentation plus a formalised scope frame.
 * Generation is PROPOSE-ONLY — a draft button asks the backend to draft a document, which the
 * operator then edits and approves. Nothing on this panel runs a command or gates one; the
 * RoE is a written frame the human approves against, never a machine veto.
 */

type Tab = "opplan" | "roe" | "conops" | "deconfliction" | "attack";

const TABS: { key: Tab; label: string }[] = [
  { key: "opplan", label: "OPPLAN" },
  { key: "roe", label: "RoE" },
  { key: "conops", label: "ConOps" },
  { key: "deconfliction", label: "Deconfliction" },
  { key: "attack", label: "ATT&CK" },
];

const STATUS_COLUMNS: { key: Objective["status"]; label: string }[] = [
  { key: "pending", label: "Pending" },
  { key: "in-progress", label: "In progress" },
  { key: "completed", label: "Completed" },
  { key: "blocked", label: "Blocked" },
  { key: "cancelled", label: "Cancelled" },
];

// The OPPLAN status state machine, mirrored on the client so the board only offers legal
// next states. The backend re-validates — this is a convenience, not the control.
const NEXT_STATES: Record<string, Objective["status"][]> = {
  pending: ["in-progress", "blocked", "cancelled"],
  "in-progress": ["completed", "blocked", "cancelled"],
  blocked: ["in-progress", "cancelled"],
  completed: [],
  cancelled: [],
};

export function GovernancePanel({ id, initialTab }: { id: string; initialTab?: Tab }) {
  const [pkg, setPkg] = useState<GovernancePackage | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>(initialTab ?? "opplan");
  const [busy, setBusy] = useState<string | null>(null);

  const reload = useCallback(
    (signal?: AbortSignal) =>
      getGovernance(id, signal)
        .then((p) => {
          setPkg(p);
          setErr(null);
        })
        .catch((e) => setErr(e instanceof Error ? e.message : "failed to load governance")),
    [id]
  );

  useEffect(() => {
    const ac = new AbortController();
    reload(ac.signal);
    return () => ac.abort();
  }, [reload]);

  if (err) {
    return <div className="hp-gov-error">{err}</div>;
  }
  if (!pkg) {
    return <p className="hp-gov-loading">loading governance…</p>;
  }

  return (
    <section className="hp-gov" aria-label="Engagement governance">
      <div className="hp-gov-topline">
        <span className="hp-gov-kicker">engagement governance</span>
        <span className="hp-gov-frame">
          RoE · ConOps · Deconfliction · OPPLAN — propose-only; human approves each command
          inside this frame
        </span>
      </div>

      <ScopeBanner check={pkg.scope_check} />

      <nav className="hp-gov-tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            className={`hp-gov-tab${tab === t.key ? " is-active" : ""}`}
            onClick={() => setTab(t.key)}
          >
            {t.label}
            <TabBadge tab={t.key} pkg={pkg} />
          </button>
        ))}
      </nav>

      <div className="hp-gov-body">
        {tab === "opplan" && (
          <OpplanTab id={id} pkg={pkg} reload={reload} busy={busy} setBusy={setBusy} />
        )}
        {tab === "roe" && (
          <DocTab id={id} docType="roe" doc={pkg.roe} reload={reload} busy={busy} setBusy={setBusy} />
        )}
        {tab === "conops" && (
          <DocTab id={id} docType="conops" doc={pkg.conops} reload={reload} busy={busy} setBusy={setBusy} />
        )}
        {tab === "deconfliction" && (
          <DocTab
            id={id}
            docType="deconfliction"
            doc={pkg.deconfliction}
            reload={reload}
            busy={busy}
            setBusy={setBusy}
          />
        )}
        {tab === "attack" && <AttackTab pkg={pkg} />}
      </div>
    </section>
  );
}

function TabBadge({ tab, pkg }: { tab: Tab; pkg: GovernancePackage }) {
  if (tab === "opplan") {
    const n = pkg.opplan.summary.total;
    return n ? <span className="hp-gov-tabbadge">{n}</span> : null;
  }
  if (tab === "attack") {
    const c = pkg.opplan.attack_coverage.counts;
    return c.techniques_covered ? (
      <span className="hp-gov-tabbadge">{c.techniques_covered}</span>
    ) : null;
  }
  const doc = tab === "roe" ? pkg.roe : tab === "conops" ? pkg.conops : pkg.deconfliction;
  if (doc.approved) return <span className="hp-gov-tabbadge is-ok">✓</span>;
  if (doc.version > 0) return <span className="hp-gov-tabbadge is-draft">draft</span>;
  return null;
}

function ScopeBanner({ check }: { check: GovernancePackage["scope_check"] }) {
  const tone =
    check.status === "ok"
      ? "is-ok"
      : check.status === "mismatch" || check.status === "invalid"
        ? "is-warn"
        : "is-dim";
  const label =
    check.status === "ok"
      ? "RoE scope formalises the handrail"
      : check.status === "undeclared"
        ? "RoE scope not declared"
        : check.status === "invalid"
          ? "RoE scope does not parse"
          : check.status === "mismatch"
            ? "RoE scope differs from the live handrail"
            : check.status;
  return (
    <div className={`hp-gov-scope ${tone}`}>
      <span className="hp-gov-scope-badge">scope</span>
      <span className="hp-gov-scope-label">{label}</span>
      {check.declared_scope && (
        <code className="hp-gov-scope-spec">{check.declared_scope}</code>
      )}
      {check.unbounded && <span className="hp-gov-scope-unbounded">unbounded ·  *</span>}
      <span className="hp-gov-scope-advisory">
        advisory — human approval remains the bound
      </span>
      {check.notes.length > 0 && (
        <ul className="hp-gov-scope-notes">
          {check.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/* --------------------------------------------------------------------------- */
/* OPPLAN — objectives board + summary                                          */
/* --------------------------------------------------------------------------- */
function OpplanTab({
  id,
  pkg,
  reload,
  busy,
  setBusy,
}: {
  id: string;
  pkg: GovernancePackage;
  reload: () => Promise<void>;
  busy: string | null;
  setBusy: (v: string | null) => void;
}) {
  const opplan = pkg.opplan;
  const [newTitle, setNewTitle] = useState("");
  const [newPhase, setNewPhase] = useState(pkg.phases[0] ?? "recon");
  const [newTech, setNewTech] = useState("");

  const draftOpplan = async () => {
    setBusy("opplan-draft");
    try {
      const drafted = await draftGovernanceDoc(id, "opplan");
      const objectives = (drafted.payload.objectives as Record<string, unknown>[]) ?? [];
      // persist the OPPLAN settings + create the proposed objectives as PENDING rows to edit
      await saveGovernanceDoc(id, "opplan", drafted.payload);
      if (objectives.length) await seedOpplan(id, objectives);
      await reload();
    } finally {
      setBusy(null);
    }
  };

  const add = async () => {
    if (!newTitle.trim()) return;
    setBusy("obj-add");
    try {
      await addObjective(id, {
        title: newTitle.trim(),
        phase: newPhase,
        technique_ids: newTech.trim() ? newTech.split(/[\s,]+/).filter(Boolean) : [],
      });
      setNewTitle("");
      setNewTech("");
      await reload();
    } finally {
      setBusy(null);
    }
  };

  const move = async (obj: Objective, status: Objective["status"]) => {
    setBusy(`obj-${obj.obj_id}`);
    try {
      await updateObjective(id, obj.obj_id, { status });
      await reload();
    } catch {
      /* an illegal transition is refused by the backend; reload shows the true state */
      await reload();
    } finally {
      setBusy(null);
    }
  };

  const remove = async (obj: Objective) => {
    setBusy(`obj-${obj.obj_id}`);
    try {
      await deleteObjective(id, obj.obj_id);
      await reload();
    } finally {
      setBusy(null);
    }
  };

  const s = opplan.summary;

  return (
    <div className="hp-gov-opplan">
      <div className="hp-gov-summary">
        <SummaryStat n={s.total} label="objectives" tone="total" />
        <SummaryStat n={s.pending} label="pending" tone="pending" />
        <SummaryStat n={s.in_progress} label="in progress" tone="in-progress" />
        <SummaryStat n={s.completed} label="completed" tone="completed" />
        <SummaryStat n={s.blocked} label="blocked" tone="blocked" />
        <SummaryStat n={s.cancelled} label="cancelled" tone="cancelled" />
        <span className="hp-gov-version">OPPLAN v{opplan.version}</span>
      </div>

      <div className="hp-gov-objform">
        <input
          className="hp-gov-input"
          value={newTitle}
          onChange={(e) => setNewTitle(e.target.value)}
          placeholder="New objective — e.g. Gain initial access to the DMZ web host"
          spellCheck={false}
        />
        <select
          className="hp-gov-select"
          value={newPhase}
          onChange={(e) => setNewPhase(e.target.value)}
          aria-label="Objective phase"
        >
          {pkg.phases.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <input
          className="hp-gov-input hp-gov-input-tech"
          value={newTech}
          onChange={(e) => setNewTech(e.target.value)}
          placeholder="ATT&CK ids (T1190 T1078)"
          spellCheck={false}
        />
        <button
          className="hp-gov-btn"
          onClick={add}
          disabled={busy === "obj-add" || !newTitle.trim()}
        >
          add objective
        </button>
        <button
          className="hp-gov-btn hp-gov-btn-ghost"
          onClick={draftOpplan}
          disabled={busy === "opplan-draft"}
          title="Propose an OPPLAN from the scope + target. You edit and approve — nothing runs."
        >
          {busy === "opplan-draft" ? "drafting…" : "draft OPPLAN (propose)"}
        </button>
      </div>

      {opplan.objectives.length === 0 ? (
        <p className="hp-gov-empty">
          No objectives yet. Add one, or draft an OPPLAN — objectives drive the orchestrator&apos;s
          targeting, each step still human-approved.
        </p>
      ) : (
        <div className="hp-gov-board">
          {STATUS_COLUMNS.map((col) => {
            const items = opplan.objectives.filter((o) => o.status === col.key);
            return (
              <div key={col.key} className={`hp-gov-col hp-gov-col-${col.key}`}>
                <div className="hp-gov-col-head">
                  <span className="hp-gov-col-label">{col.label}</span>
                  <span className="hp-gov-col-count">{items.length}</span>
                </div>
                <div className="hp-gov-col-body">
                  {items.map((o) => (
                    <ObjectiveCard
                      key={o.obj_id}
                      obj={o}
                      busy={busy === `obj-${o.obj_id}`}
                      onMove={move}
                      onRemove={remove}
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function SummaryStat({ n, label, tone }: { n: number; label: string; tone: string }) {
  return (
    <div className={`hp-gov-stat hp-gov-stat-${tone}`}>
      <span className="hp-gov-stat-n">{n}</span>
      <span className="hp-gov-stat-label">{label}</span>
    </div>
  );
}

function ObjectiveCard({
  obj,
  busy,
  onMove,
  onRemove,
}: {
  obj: Objective;
  busy: boolean;
  onMove: (o: Objective, s: Objective["status"]) => void;
  onRemove: (o: Objective) => void;
}) {
  const nexts = NEXT_STATES[obj.status] ?? [];
  return (
    <article className={`hp-gov-obj${busy ? " is-busy" : ""}`}>
      <div className="hp-gov-obj-top">
        <span className="hp-gov-obj-id">{obj.obj_id}</span>
        <span className={`hp-gov-phase hp-gov-phase-${obj.phase}`}>{obj.phase}</span>
        <span className={`hp-gov-opsec hp-gov-opsec-${obj.opsec}`}>{obj.opsec}</span>
      </div>
      <h4 className="hp-gov-obj-title">{obj.title}</h4>
      {obj.techniques.length > 0 && (
        <div className="hp-gov-obj-techs">
          {obj.techniques.map((t) => (
            <span
              key={t.id}
              className={`hp-gov-tech${t.known ? "" : " is-unmapped"}`}
              title={t.known ? t.name : `${t.id} — not in the ATT&CK reference`}
            >
              {t.id}
            </span>
          ))}
        </div>
      )}
      {obj.evidence_run_id && (
        <div className="hp-gov-obj-evidence">advanced by run {obj.evidence_run_id}</div>
      )}
      <div className="hp-gov-obj-actions">
        {nexts.map((ns) => (
          <button
            key={ns}
            className="hp-gov-obj-move"
            onClick={() => onMove(obj, ns)}
            disabled={busy}
          >
            → {ns}
          </button>
        ))}
        {nexts.length === 0 && <span className="hp-gov-obj-terminal">terminal</span>}
        <button
          className="hp-gov-obj-del"
          onClick={() => onRemove(obj)}
          disabled={busy}
          aria-label="Delete objective"
          title="Delete objective"
        >
          ×
        </button>
      </div>
    </article>
  );
}

/* --------------------------------------------------------------------------- */
/* RoE / ConOps / Deconfliction — a document with draft + approve               */
/* --------------------------------------------------------------------------- */
function DocTab({
  id,
  docType,
  doc,
  reload,
  busy,
  setBusy,
}: {
  id: string;
  docType: GovDocType;
  doc: GovDoc;
  reload: () => Promise<void>;
  busy: string | null;
  setBusy: (v: string | null) => void;
}) {
  const [source, setSource] = useState<string | null>(null);

  const draft = async () => {
    setBusy(`${docType}-draft`);
    try {
      const drafted = await draftGovernanceDoc(id, docType);
      setSource(drafted.source);
      await saveGovernanceDoc(id, docType, drafted.payload);
      await reload();
    } finally {
      setBusy(null);
    }
  };

  const approve = async () => {
    setBusy(`${docType}-approve`);
    try {
      await approveGovernanceDoc(id, docType, "operator");
      await reload();
    } finally {
      setBusy(null);
    }
  };

  const drafted = doc.version > 0;

  return (
    <div className="hp-gov-doc">
      <div className="hp-gov-doc-bar">
        <div className="hp-gov-doc-status">
          {doc.approved ? (
            <span className="hp-gov-approved">✓ approved{doc.approved_by ? ` · ${doc.approved_by}` : ""}</span>
          ) : drafted ? (
            <span className="hp-gov-unapproved">drafted · awaiting approval</span>
          ) : (
            <span className="hp-gov-none">not drafted</span>
          )}
          <span className="hp-gov-doc-version">v{doc.version}</span>
          {source && <span className="hp-gov-doc-src">source: {source}</span>}
        </div>
        <div className="hp-gov-doc-actions">
          <button className="hp-gov-btn hp-gov-btn-ghost" onClick={draft} disabled={busy === `${docType}-draft`}>
            {busy === `${docType}-draft` ? "drafting…" : drafted ? "re-draft (propose)" : "draft (propose)"}
          </button>
          <button
            className="hp-gov-btn"
            onClick={approve}
            disabled={!drafted || doc.approved || busy === `${docType}-approve`}
          >
            approve
          </button>
        </div>
      </div>

      {!drafted ? (
        <p className="hp-gov-empty">
          Draft this document (propose-only) from the engagement scope + target, then edit and
          approve. Nothing is live until you approve — and approval frames the human gate, it
          does not replace it.
        </p>
      ) : (
        <DocBody docType={docType} payload={doc.payload} />
      )}
    </div>
  );
}

function DocBody({
  docType,
  payload,
}: {
  docType: GovDocType;
  payload: Record<string, unknown>;
}) {
  if (docType === "roe") return <RoeBody p={payload} />;
  if (docType === "conops") return <ConopsBody p={payload} />;
  return <DeconflictionBody p={payload} />;
}

function asList(v: unknown): string[] {
  return Array.isArray(v) ? v.map((x) => String(x)) : [];
}
function asStr(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="hp-gov-field">
      <div className="hp-gov-field-label">{label}</div>
      <div className="hp-gov-field-val">{children}</div>
    </div>
  );
}

function Chips({ items, tone }: { items: string[]; tone?: string }) {
  if (!items.length) return <span className="hp-gov-muted">—</span>;
  return (
    <div className="hp-gov-chips">
      {items.map((it, i) => (
        <span key={i} className={`hp-gov-chip${tone ? ` hp-gov-chip-${tone}` : ""}`}>
          {it}
        </span>
      ))}
    </div>
  );
}

function RoeBody({ p }: { p: Record<string, unknown> }) {
  return (
    <div className="hp-gov-fields">
      <Field label="Authorized scope (references the scope model)">
        <code className="hp-gov-scope-spec">{asStr(p.scope_spec) || "—"}</code>
      </Field>
      <Field label="Authorized techniques">
        <Chips items={asList(p.authorized_techniques)} tone="ok" />
      </Field>
      <Field label="Forbidden techniques">
        <Chips items={asList(p.forbidden_techniques)} tone="warn" />
      </Field>
      <Field label="OPSEC level">
        <span className="hp-gov-chip">{asStr(p.opsec_level) || "standard"}</span>
      </Field>
      <Field label="Time windows">
        <Chips items={asList(p.time_windows)} />
      </Field>
      <Field label="Excluded targets">
        <Chips items={asList(p.excluded_targets)} tone="warn" />
      </Field>
      <Field label="Excluded actions">
        <Chips items={asList(p.excluded_actions)} tone="warn" />
      </Field>
      <Field label="Sensitive-data handling">
        <p className="hp-gov-prose">{asStr(p.sensitive_data_handling) || "—"}</p>
      </Field>
      <Field label="Stop conditions">
        <ul className="hp-gov-ul">
          {asList(p.stop_conditions).map((c, i) => (
            <li key={i}>{c}</li>
          ))}
        </ul>
      </Field>
      <Field label="Emergency contacts">
        <Chips items={asList(p.emergency_contacts)} />
      </Field>
    </div>
  );
}

function ConopsBody({ p }: { p: Record<string, unknown> }) {
  const phases = Array.isArray(p.phases) ? (p.phases as Record<string, unknown>[]) : [];
  return (
    <div className="hp-gov-fields">
      <Field label="Approach">
        <p className="hp-gov-prose">{asStr(p.approach) || "—"}</p>
      </Field>
      <Field label="Phases">
        <ol className="hp-gov-phases-list">
          {phases.map((ph, i) => (
            <li key={i} className="hp-gov-phase-item">
              <span className="hp-gov-phase-name">{asStr(ph.name)}</span>
              <span className="hp-gov-phase-desc">{asStr(ph.description)}</span>
              {asStr(ph.success_criteria) && (
                <span className="hp-gov-phase-crit">✓ {asStr(ph.success_criteria)}</span>
              )}
            </li>
          ))}
        </ol>
      </Field>
      <Field label="Success criteria">
        <ul className="hp-gov-ul">
          {asList(p.success_criteria).map((c, i) => (
            <li key={i}>{c}</li>
          ))}
        </ul>
      </Field>
    </div>
  );
}

function DeconflictionBody({ p }: { p: Record<string, unknown> }) {
  return (
    <div className="hp-gov-fields">
      <Field label="Engagement signature">
        <code className="hp-gov-sig">{asStr(p.engagement_signature) || "—"}</code>
      </Field>
      <Field label="Source markers">
        <Chips items={asList(p.source_markers)} />
      </Field>
      <Field label="Notification contacts">
        <Chips items={asList(p.notification_contacts)} />
      </Field>
      <Field label="Traffic identification">
        <p className="hp-gov-prose">{asStr(p.traffic_identification) || "—"}</p>
      </Field>
      <Field label="Blue-team coordination notes">
        <p className="hp-gov-prose">{asStr(p.blue_team_notes) || "—"}</p>
      </Field>
    </div>
  );
}

/* --------------------------------------------------------------------------- */
/* ATT&CK coverage                                                              */
/* --------------------------------------------------------------------------- */
function AttackTab({ pkg }: { pkg: GovernancePackage }) {
  const cov = pkg.opplan.attack_coverage;
  const c = cov.counts;
  return (
    <div className="hp-gov-attack">
      <div className="hp-gov-attack-summary">
        <SummaryStat n={c.tactics_touched} label={`/ ${c.tactics_total} tactics`} tone="total" />
        <SummaryStat
          n={c.techniques_covered}
          label={`/ ${c.techniques_total} techniques`}
          tone="completed"
        />
        <SummaryStat n={c.exercised_unique} label="unique mapped" tone="in-progress" />
        {c.unmapped.length > 0 && (
          <div className="hp-gov-unmapped">
            <span className="hp-gov-unmapped-label">unmapped:</span>
            {c.unmapped.map((u) => (
              <span key={u} className="hp-gov-tech is-unmapped">
                {u}
              </span>
            ))}
          </div>
        )}
      </div>
      <div className="hp-gov-matrix">
        {cov.grid.map((tac) => (
          <div key={tac.tactic_id} className={`hp-gov-tactic${tac.covered ? " is-covered" : ""}`}>
            <div className="hp-gov-tactic-head">
              <span className="hp-gov-tactic-name">{tac.tactic_name}</span>
              <span className="hp-gov-tactic-id">{tac.tactic_id}</span>
            </div>
            <div className="hp-gov-tactic-techs">
              {tac.techniques.map((t) => (
                <span
                  key={t.id}
                  className={`hp-gov-cell${t.covered ? " is-covered" : ""}`}
                  title={`${t.id} · ${t.name}`}
                >
                  {t.id}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
