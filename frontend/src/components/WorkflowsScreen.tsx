"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { PageShell } from "./PageShell";
import {
  ApiError,
  createWorkflow,
  deleteWorkflow,
  exportWorkflow,
  importWorkflow,
  listWorkflows,
  planWorkflow,
  runWorkflow,
  sampleWorkflow,
  updateWorkflow,
  type Workflow,
  type WorkflowBounds,
  type WorkflowIndex,
  type WorkflowPlan,
  type WorkflowRun,
  type WorkflowStepResult,
  type WfOutputField,
  type WfStep,
} from "@/lib/api";

/**
 * :workflows — the reusable prompt-workflow BUILDER, ported from open·kritt.
 *
 * *** AUTHORING EXECUTES NOTHING. *** Composing, editing, importing and exporting a workflow only
 * read and write a store — they launch no agent and touch no target. RUNNING one is the SAME "one
 * approved job" the AI code-audit is (the fan-out justification), and it adds NO new gate: each
 * step renders its prompt, calls the audit's LLM agent, and threads outputs downstream. A COMMAND
 * step is a proposal (approve-each), never run from here. An IMPORTED workflow is surfaced for
 * inspection and is NEVER auto-run — the operator reads the prompts, then chooses to run it.
 */
const SEV_COLOR: Record<string, string> = {
  critical: "#ff5c7a",
  high: "#f0776a",
  medium: "#f0a24a",
  low: "#7ec8a0",
  informational: "#8aa4c8",
  info: "#8aa4c8",
};

function newStep(n: number): WfStep {
  return {
    id: `step${n}`,
    title: `Step ${n}`,
    prompt: "Repo: {{repo}}. ",
    kind: "analyze",
    batch_over: "",
    item_var: "item",
    siblings: 1,
    depth: 0,
    output_format: [],
    grounded: false,
    note: "",
  };
}

function blankWorkflow(): Workflow {
  return {
    id: "",
    name: "",
    description: "",
    steps: [newStep(1)],
    playbook: "",
    builtin: false,
    imported: false,
    version: 0,
    updated_at: 0,
  };
}

function slugify(name: string): string {
  return name.trim().toLowerCase().replace(/[^\w-]+/g, "-").replace(/^-+|-+$/g, "") || "workflow";
}

export function WorkflowsScreen() {
  const [index, setIndex] = useState<WorkflowIndex | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [draft, setDraft] = useState<Workflow | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [focusedStep, setFocusedStep] = useState<string | null>(null);

  const [plan, setPlan] = useState<WorkflowPlan | null>(null);
  const [exportText, setExportText] = useState("");
  const [importText, setImportText] = useState("");

  const [repoPath, setRepoPath] = useState("codescan/sample_app");
  const [sessionId, setSessionId] = useState("");
  const [runMode, setRunMode] = useState("auto");
  const [run, setRun] = useState<WorkflowRun | null>(null);
  const [running, setRunning] = useState(false);

  const bounds: WorkflowBounds | undefined = index?.bounds;

  const refresh = useCallback(
    (selectId?: string) => {
      listWorkflows()
        .then((idx) => {
          setIndex(idx);
          const pick =
            (selectId && idx.workflows.find((w) => w.id === selectId)) ||
            idx.workflows[0] ||
            null;
          if (pick) {
            setDraft(structuredClone(pick));
            setIsNew(false);
            setDirty(false);
          }
        })
        .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
    },
    []
  );

  useEffect(() => {
    refresh();
  }, [refresh]);

  const select = useCallback((wf: Workflow) => {
    setDraft(structuredClone(wf));
    setIsNew(false);
    setDirty(false);
    setPlan(null);
    setRun(null);
    setExportText("");
    setError(null);
    setNotice(wf.imported ? "Imported workflow — inspect the step prompts before you run it." : null);
  }, []);

  const startNew = useCallback(() => {
    const wf = blankWorkflow();
    wf.id = "";
    wf.name = "New workflow";
    setDraft(wf);
    setIsNew(true);
    setDirty(true);
    setPlan(null);
    setRun(null);
    setNotice(null);
    setError(null);
  }, []);

  const cloneCurrent = useCallback(() => {
    if (!draft) return;
    const wf = structuredClone(draft);
    wf.id = "";
    wf.name = `${draft.name} (copy)`;
    wf.builtin = false;
    wf.imported = false;
    setDraft(wf);
    setIsNew(true);
    setDirty(true);
    setNotice("Editable copy — set a name and save it.");
  }, [draft]);

  // ----- draft mutation helpers (all through event handlers -> lint-safe) --- //
  const mutate = useCallback((fn: (w: Workflow) => void) => {
    setDraft((cur) => {
      if (!cur) return cur;
      const next = structuredClone(cur);
      fn(next);
      return next;
    });
    setDirty(true);
  }, []);

  const patchStep = useCallback(
    (id: string, partial: Partial<WfStep>) =>
      mutate((w) => {
        const s = w.steps.find((x) => x.id === id);
        if (s) Object.assign(s, partial);
      }),
    [mutate]
  );

  const addStep = useCallback(
    () => mutate((w) => w.steps.push(newStep(w.steps.length + 1))),
    [mutate]
  );

  const removeStep = useCallback(
    (id: string) => mutate((w) => (w.steps = w.steps.filter((s) => s.id !== id))),
    [mutate]
  );

  const insertVar = useCallback(
    (name: string) => {
      const target = focusedStep ?? draft?.steps[0]?.id ?? null;
      if (!target) return;
      mutate((w) => {
        const s = w.steps.find((x) => x.id === target);
        if (s) s.prompt = `${s.prompt}{{${name}}}`;
      });
    },
    [focusedStep, draft, mutate]
  );

  const addField = useCallback(
    (stepId: string) =>
      mutate((w) => {
        const s = w.steps.find((x) => x.id === stepId);
        if (s)
          s.output_format.push({ name: "field", type: "string", required: false, label: "" });
      }),
    [mutate]
  );

  const patchField = useCallback(
    (stepId: string, i: number, partial: Partial<WfOutputField>) =>
      mutate((w) => {
        const s = w.steps.find((x) => x.id === stepId);
        if (s && s.output_format[i]) Object.assign(s.output_format[i], partial);
      }),
    [mutate]
  );

  const removeField = useCallback(
    (stepId: string, i: number) =>
      mutate((w) => {
        const s = w.steps.find((x) => x.id === stepId);
        if (s) s.output_format.splice(i, 1);
      }),
    [mutate]
  );

  // ----- persistence (authoring — executes nothing) ------------------------ //
  const save = useCallback(() => {
    if (!draft) return;
    setError(null);
    const id = draft.id.trim() || slugify(draft.name);
    const body = {
      id,
      name: draft.name,
      description: draft.description,
      playbook: draft.playbook,
      steps: draft.steps,
    };
    const p = isNew
      ? createWorkflow(body)
      : updateWorkflow(draft.id, { ...body, expected_version: draft.version });
    Promise.resolve(p)
      .then((saved) => {
        setNotice(`Saved “${saved?.name ?? id}”.`);
        setDirty(false);
        refresh(saved?.id ?? id);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [draft, isNew, refresh]);

  const remove = useCallback(() => {
    if (!draft || draft.builtin || isNew) return;
    deleteWorkflow(draft.id)
      .then(() => {
        setNotice(`Deleted “${draft.name}”.`);
        refresh();
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [draft, isNew, refresh]);

  const doExport = useCallback(() => {
    if (!draft || isNew) return;
    exportWorkflow(draft.id)
      .then((json) => setExportText(JSON.stringify(json, null, 2)))
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [draft, isNew]);

  const doImport = useCallback(() => {
    setError(null);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(importText);
    } catch {
      setError("That is not valid JSON.");
      return;
    }
    importWorkflow(parsed)
      .then((r) => {
        setImportText("");
        setNotice(r.note);
        refresh(r.workflow.id);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [importText, refresh]);

  const doPlan = useCallback(() => {
    if (!draft || isNew) return;
    planWorkflow(draft.id)
      .then(setPlan)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [draft, isNew]);

  // ----- run (one approved job) + offline sample --------------------------- //
  const doRun = useCallback(() => {
    if (!draft || isNew || running) return;
    setRunning(true);
    setError(null);
    runWorkflow(draft.id, { path: repoPath, session_id: sessionId.trim() || null, mode: runMode })
      .then((r) => {
        setRun(r);
        if (r.persisted) setNotice(`Persisted ${r.persisted} finding(s) to engagement state.`);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setRunning(false));
  }, [draft, isNew, running, repoPath, sessionId, runMode]);

  const loadSample = useCallback(() => {
    if (!draft || isNew) return;
    setRunning(true);
    sampleWorkflow(draft.id)
      .then(setRun)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setRunning(false));
  }, [draft, isNew]);

  const priorStepVars = useMemo(() => {
    if (!draft) return [];
    return draft.steps.map((s) => `steps.${s.id}.output`);
  }, [draft]);

  const readOnly = !!draft?.builtin;

  return (
    <PageShell crumbs={[{ label: "code-scan", href: "/code-scan" }, { label: "workflows" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">compose · variables · batch/depth/siblings · import/export · run</div>
          <h1 className="hp-tn-title">:workflows</h1>
          <p className="hp-tn-sub">
            Author your own reusable prompt-step playbooks over the AI code-audit fan-out. Each step
            is a focused prompt with <strong>variables</strong>, an output schema and a{" "}
            <strong>batch / depth / siblings</strong> fan-out shape. <strong>Authoring executes
            nothing</strong>; a run is the audit&rsquo;s <strong>one approved job</strong> — no new
            gate — command steps are approve-each, and an imported workflow is{" "}
            <strong>inspected before it is ever run</strong>.
          </p>
        </header>

        {error && <p className="hp-tn-error">{error}</p>}
        {notice && <p className="hp-tn-note">{notice}</p>}

        <div className="hp-wf-grid">
          {/* ---- workflow list ------------------------------------------- */}
          <aside className="hp-wf-aside">
            <div className="hp-tn-cardhead">
              Workflows
              <button className="hp-wf-btn is-primary" onClick={startNew}>
                + New
              </button>
            </div>
            {!index && <p className="hp-tn-note">Loading…</p>}
            <ul className="hp-tn-list">
              {index?.workflows.map((wf) => (
                <li key={wf.id}>
                  <button
                    className={`hp-wf-item${draft?.id === wf.id && !isNew ? " is-active" : ""}`}
                    onClick={() => select(wf)}
                  >
                    <span className="hp-wf-itemname">{wf.name}</span>
                    <span className="hp-wf-meta">
                      {wf.steps.length} step{wf.steps.length === 1 ? "" : "s"}
                      {wf.builtin && <span className="hp-wf-badge is-builtin">built-in</span>}
                      {wf.imported && <span className="hp-wf-badge is-imported">imported</span>}
                    </span>
                  </button>
                </li>
              ))}
            </ul>

            {/* import */}
            <div className="hp-tn-card">
              <div className="hp-tn-cardhead">Import a workflow</div>
              <p className="hp-tn-cardsub">
                Paste an exported JSON. It is stored and <strong>surfaced for inspection</strong> —
                never auto-run.
              </p>
              <textarea
                className="hp-wf-json"
                rows={4}
                placeholder='{"kritt_workflow_schema": 1, "workflow": { … }}'
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
              />
              <button className="hp-wf-btn" disabled={!importText.trim()} onClick={doImport}>
                Import (inspect-before-run)
              </button>
            </div>
          </aside>

          {/* ---- editor -------------------------------------------------- */}
          <section className="hp-wf-main">
            {!draft && <p className="hp-wf-empty">Select or create a workflow to begin.</p>}
            {draft && (
              <>
                <div className="hp-tn-card">
                  <div className="hp-tn-cardhead">
                    {isNew ? "New workflow" : draft.name}
                    <span className="hp-wf-btnrow">
                      {readOnly ? (
                        <button className="hp-wf-btn is-primary" onClick={cloneCurrent}>
                          Clone to edit
                        </button>
                      ) : (
                        <button className="hp-wf-btn is-primary" disabled={!dirty} onClick={save}>
                          {isNew ? "Create" : "Save"}
                        </button>
                      )}
                      {!isNew && !readOnly && (
                        <button className="hp-wf-btn is-danger" onClick={remove}>
                          Delete
                        </button>
                      )}
                    </span>
                  </div>
                  {readOnly && (
                    <p className="hp-tn-note">
                      A built-in workflow is read-only — clone it to make an editable copy.
                    </p>
                  )}
                  {draft.imported && (
                    <p className="hp-wf-banner">
                      ⚠ Imported — read every step prompt below before running this workflow.
                    </p>
                  )}
                  <div className="hp-wf-cols">
                    <label className="hp-wf-col">
                      <span>Name</span>
                      <input
                        value={draft.name}
                        disabled={readOnly}
                        onChange={(e) => mutate((w) => (w.name = e.target.value))}
                      />
                    </label>
                    <label className="hp-wf-col">
                      <span>Playbook (optional — enables an offline run)</span>
                      <input
                        value={draft.playbook}
                        disabled={readOnly}
                        placeholder="external-flow-analysis / evm-external-flow"
                        onChange={(e) => mutate((w) => (w.playbook = e.target.value))}
                      />
                    </label>
                  </div>
                  <label className="hp-wf-col">
                    <span>Description</span>
                    <input
                      value={draft.description}
                      disabled={readOnly}
                      onChange={(e) => mutate((w) => (w.description = e.target.value))}
                    />
                  </label>
                </div>

                {/* variable palette */}
                <div className="hp-tn-card">
                  <div className="hp-tn-cardhead">Variables</div>
                  <p className="hp-tn-cardsub">
                    Click one to insert <code>{"{{var}}"}</code> into the focused step&rsquo;s
                    prompt. Prior steps are reachable by their dotted output ref.
                  </p>
                  <div className="hp-wf-varbar">
                    {index?.builtin_variables.map((v) => (
                      <button
                        key={v.name}
                        className="hp-wf-var"
                        title={v.desc}
                        disabled={readOnly}
                        onClick={() => insertVar(v.name)}
                      >
                        {`{{${v.name}}}`}
                      </button>
                    ))}
                    {priorStepVars.map((v) => (
                      <button
                        key={v}
                        className="hp-wf-var is-step"
                        disabled={readOnly}
                        onClick={() => insertVar(v)}
                      >
                        {`{{${v}}}`}
                      </button>
                    ))}
                  </div>
                </div>

                {/* steps */}
                {draft.steps.map((s, i) => (
                  <div className="hp-wf-step" key={s.id}>
                    <div className="hp-wf-steptop">
                      <span className="hp-wf-stepnum">{i + 1}</span>
                      <input
                        className="hp-wf-title"
                        value={s.title}
                        disabled={readOnly}
                        onChange={(e) => patchStep(s.id, { title: e.target.value })}
                      />
                      <select
                        value={s.kind}
                        disabled={readOnly}
                        onChange={(e) => patchStep(s.id, { kind: e.target.value })}
                      >
                        {index?.step_kinds.map((k) => (
                          <option key={k} value={k}>
                            {k}
                          </option>
                        ))}
                      </select>
                      {!readOnly && draft.steps.length > 1 && (
                        <button className="hp-tn-stop" onClick={() => removeStep(s.id)}>
                          remove
                        </button>
                      )}
                    </div>

                    <input
                      className="hp-wf-stepid"
                      value={s.id}
                      disabled={readOnly}
                      onChange={(e) =>
                        patchStep(s.id, { id: e.target.value.replace(/[^\w-]/g, "") })
                      }
                      aria-label="step id"
                    />

                    <textarea
                      className="hp-wf-json"
                      rows={4}
                      value={s.prompt}
                      disabled={readOnly}
                      onFocus={() => setFocusedStep(s.id)}
                      onChange={(e) => patchStep(s.id, { prompt: e.target.value })}
                    />

                    {/* fan-out controls */}
                    <div className="hp-wf-fanout">
                      {s.kind === "batch" && (
                        <>
                          <label className="hp-wf-fld">
                            <span>batch over</span>
                            <input
                              value={s.batch_over}
                              disabled={readOnly}
                              placeholder="steps.enum.output.0.items"
                              onChange={(e) => patchStep(s.id, { batch_over: e.target.value })}
                            />
                          </label>
                          <label className="hp-wf-fld">
                            <span>item var</span>
                            <input
                              value={s.item_var}
                              disabled={readOnly}
                              onChange={(e) => patchStep(s.id, { item_var: e.target.value })}
                            />
                          </label>
                          <label className="hp-wf-fld">
                            <span>depth (0–{bounds?.max_depth ?? 4})</span>
                            <input
                              type="number"
                              min={0}
                              max={bounds?.max_depth ?? 4}
                              value={s.depth}
                              disabled={readOnly}
                              onChange={(e) =>
                                patchStep(s.id, { depth: Number.parseInt(e.target.value, 10) || 0 })
                              }
                            />
                          </label>
                        </>
                      )}
                      <label className="hp-wf-fld">
                        <span>siblings (1–{bounds?.max_siblings ?? 8})</span>
                        <input
                          type="number"
                          min={1}
                          max={bounds?.max_siblings ?? 8}
                          value={s.siblings}
                          disabled={readOnly}
                          onChange={(e) =>
                            patchStep(s.id, { siblings: Number.parseInt(e.target.value, 10) || 1 })
                          }
                        />
                      </label>
                      <label className="hp-wf-fld hp-wf-fld-check">
                        <input
                          type="checkbox"
                          checked={s.grounded}
                          disabled={readOnly}
                          onChange={(e) => patchStep(s.id, { grounded: e.target.checked })}
                        />
                        <span>KB-ground</span>
                      </label>
                    </div>

                    {/* output schema */}
                    {s.kind !== "command" && (
                      <div className="hp-wf-fields">
                        <div className="hp-tn-cardsub">
                          Output schema{" "}
                          {s.output_format.length === 0 && "(default: concrete finding-or-stub)"}
                        </div>
                        {s.output_format.map((f, fi) => (
                          <div className="hp-wf-fld-row" key={fi}>
                            <input
                              value={f.name}
                              disabled={readOnly}
                              onChange={(e) => patchField(s.id, fi, { name: e.target.value })}
                            />
                            <select
                              value={f.type}
                              disabled={readOnly}
                              onChange={(e) => patchField(s.id, fi, { type: e.target.value })}
                            >
                              {index?.field_types.map((t) => (
                                <option key={t} value={t}>
                                  {t}
                                </option>
                              ))}
                            </select>
                            <label className="hp-wf-fld-check">
                              <input
                                type="checkbox"
                                checked={f.required}
                                disabled={readOnly}
                                onChange={(e) =>
                                  patchField(s.id, fi, { required: e.target.checked })
                                }
                              />
                              <span>required</span>
                            </label>
                            {!readOnly && (
                              <button className="hp-tn-stop" onClick={() => removeField(s.id, fi)}>
                                ×
                              </button>
                            )}
                          </div>
                        ))}
                        {!readOnly && (
                          <button className="hp-wf-btn" onClick={() => addField(s.id)}>
                            + field
                          </button>
                        )}
                      </div>
                    )}
                    {s.kind === "command" && (
                      <p className="hp-tn-note hp-tn-note-warn">
                        A command step PROPOSES the rendered string — approve-each in the sandbox.
                        The runner never executes it.
                      </p>
                    )}
                  </div>
                ))}

                {!readOnly && (
                  <button
                    className="hp-wf-btn"
                    disabled={(draft.steps.length ?? 0) >= (bounds?.max_steps ?? 24)}
                    onClick={addStep}
                  >
                    + Add step
                  </button>
                )}

                {/* plan + export */}
                <div className="hp-tn-card">
                  <div className="hp-tn-cardhead">
                    Fan-out plan &amp; portability
                    <span className="hp-wf-btnrow">
                      {!isNew && (
                        <button className="hp-wf-btn" onClick={doPlan}>
                          Preview plan
                        </button>
                      )}
                      {!isNew && (
                        <button className="hp-wf-btn" onClick={doExport}>
                          Export JSON
                        </button>
                      )}
                    </span>
                  </div>
                  {plan && (
                    <table className="hp-wf-plan">
                      <thead>
                        <tr>
                          <th>step</th>
                          <th>kind</th>
                          <th>items</th>
                          <th>siblings</th>
                          <th>depth</th>
                          <th>tasks</th>
                        </tr>
                      </thead>
                      <tbody>
                        {plan.steps.map((r) => (
                          <tr key={r.step_id}>
                            <td>{r.title}</td>
                            <td>{r.kind}</td>
                            <td>{String(r.items)}</td>
                            <td>{r.siblings}</td>
                            <td>{r.depth}</td>
                            <td>{String(r.tasks)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                  {plan && (
                    <p className="hp-tn-note">
                      Static tasks: {plan.static_tasks} · ceiling {plan.task_ceiling}. “dynamic” =
                      depends on a prior step&rsquo;s output, known only at run time.
                    </p>
                  )}
                  {exportText && (
                    <textarea className="hp-wf-json" rows={6} readOnly value={exportText} />
                  )}
                </div>

                {/* run */}
                <div className="hp-tn-card">
                  <div className="hp-tn-cardhead">Run — one approved job</div>
                  <p className="hp-tn-cardsub">
                    Reads a source tree and calls the audit&rsquo;s LLM agent. No new gate. Command
                    steps come back as approve-each proposals. Findings dedupe + rank; a session
                    persists them to engagement state.
                  </p>
                  <div className="hp-tn-form">
                    <input
                      placeholder="source tree folder (read-only)"
                      value={repoPath}
                      onChange={(e) => setRepoPath(e.target.value)}
                    />
                    <input
                      placeholder="session id (optional)"
                      value={sessionId}
                      onChange={(e) => setSessionId(e.target.value)}
                    />
                    <select value={runMode} onChange={(e) => setRunMode(e.target.value)}>
                      <option value="auto">auto (LLM)</option>
                      <option value="heuristic">heuristic (no LLM)</option>
                    </select>
                    <button disabled={isNew || running} onClick={doRun}>
                      {running ? "Running…" : "Run"}
                    </button>
                    {draft.builtin && (
                      <button disabled={running} onClick={loadSample}>
                        Load sample
                      </button>
                    )}
                    <Link className="hp-wf-tag" href="/code-scan">
                      open :code-scan →
                    </Link>
                  </div>
                  {run && <RunResult run={run} />}
                </div>
              </>
            )}
          </section>
        </div>
      </div>
    </PageShell>
  );
}

function RunResult({ run }: { run: WorkflowRun }) {
  return (
    <div className="hp-wf-run">
      <p className="hp-tn-note">
        {run.mode} run · {run.tasks_run} task(s) · {run.findings.length} finding(s) ·{" "}
        {run.proposals.length} proposal(s)
        {run.via_playbook ? ` · via ${run.via_playbook}` : ""} · {run.duration_s}s
      </p>
      {run.steps?.length > 0 && (
        <div className="hp-tn-chips">
          {run.steps.map((s: WorkflowStepResult) => (
            <span className="hp-tn-chip" key={s.step_id}>
              {s.step_id}: {s.tasks} task{s.tasks === 1 ? "" : "s"}
            </span>
          ))}
        </div>
      )}
      {run.findings.map((f, i) => (
        <div className="hp-wf-finding" key={i}>
          <span className="hp-wf-sev" style={{ color: SEV_COLOR[f.severity] ?? "#8aa4c8" }}>
            {f.severity}
          </span>
          <div>
            <strong>{f.title}</strong>
            {f.vuln_class && <span className="hp-wf-tag">{f.vuln_class}</span>}
            <div className="hp-tn-note">{f.attacker_path}</div>
            {f.source_refs?.length > 0 && (
              <div className="hp-wf-meta">{f.source_refs.join(", ")}</div>
            )}
          </div>
        </div>
      ))}
      {run.proposals.map((p, i) => (
        <div className="hp-wf-proposal" key={i}>
          <span className="hp-wf-tag">{p.step} · approve-each</span>
          <code>{p.command}</code>
        </div>
      ))}
      {run.warnings?.length > 0 &&
        run.warnings.map((w, i) => (
          <p className="hp-tn-note hp-tn-note-warn" key={i}>
            {w}
          </p>
        ))}
    </div>
  );
}
