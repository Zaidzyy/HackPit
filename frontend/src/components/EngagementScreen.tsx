"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  getSession,
  renameSession,
  updateStep,
  type EngagementStep,
  type Session,
  type StepState,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";

const RESULT_DEBOUNCE_MS = 700;

/**
 * The interactive engagement view: a saved attack-path you work through.
 * Per-step checked + pasted results persist to the backend (SQLite), so the
 * whole thing survives a reload — on mount it re-fetches the merged state.
 */
export function EngagementScreen({ id }: { id: string }) {
  const fetched = useApi((s) => getSession(id, s), [id]);

  // Local, optimistic per-step state keyed by the stable {phase}-{n} id. The
  // path structure itself comes from the (immutable) fetched session.
  const [state, setState] = useState<Record<string, StepState>>({});
  const [label, setLabel] = useState("");

  useEffect(() => {
    if (!fetched.data) return;
    const map: Record<string, StepState> = {};
    for (const ph of fetched.data.path.phases) {
      for (const st of ph.steps) {
        map[st.id] = { checked: st.checked, result_text: st.result_text };
      }
    }
    setState(map);
    setLabel(fetched.data.label);
  }, [fetched.data]);

  const toggle = useCallback(
    (stepId: string) => {
      setState((prev) => {
        const next = !prev[stepId]?.checked;
        // fire-and-forget persist; revert on failure
        updateStep(id, stepId, { checked: next }).catch(() => {
          setState((p) => ({
            ...p,
            [stepId]: { ...p[stepId], checked: !next },
          }));
        });
        return { ...prev, [stepId]: { ...prev[stepId], checked: next } };
      });
    },
    [id]
  );

  const saveResult = useCallback(
    (stepId: string, text: string) => {
      setState((prev) => ({
        ...prev,
        [stepId]: { ...prev[stepId], result_text: text },
      }));
      return updateStep(id, stepId, { result: text });
    },
    [id]
  );

  const commitLabel = useCallback(() => {
    const trimmed = label.trim();
    if (!fetched.data || !trimmed || trimmed === fetched.data.label) return;
    renameSession(id, trimmed).catch(() => {
      /* keep the typed value; a later edit can retry */
    });
  }, [id, label, fetched.data]);

  // ---- states ---- //
  if (fetched.loading) {
    return (
      <PageShell crumbs={[{ label: "home", href: "/" }, { label: "…" }]}>
        <div className="hp-eng">
          <p className="hp-note">loading engagement…</p>
        </div>
      </PageShell>
    );
  }

  if (fetched.error || !fetched.data) {
    return (
      <PageShell
        crumbs={[{ label: "home", href: "/" }, { label: "not found" }]}
      >
        <div className="hp-eng">
          <div className="hp-error-box">
            <p>{fetched.error ?? "Engagement not found."}</p>
            <Link href="/engagements" className="hp-back-link">
              ← your engagements
            </Link>
          </div>
        </div>
      </PageShell>
    );
  }

  const session: Session = fetched.data;
  const total = session.total;
  const checked = Object.values(state).filter((s) => s.checked).length;
  const pct = total > 0 ? Math.round((checked / total) * 100) : 0;

  return (
    <PageShell
      crumbs={[
        { label: "home", href: "/" },
        { label: "engagements", href: "/engagements" },
        { label: session.label },
      ]}
    >
      <div className="hp-eng">
        <header className="hp-eng-head">
          <div className="hp-eng-kicker">engagement</div>
          <input
            className="hp-eng-label"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            onBlur={commitLabel}
            onKeyDown={(e) => {
              if (e.key === "Enter") (e.target as HTMLInputElement).blur();
            }}
            aria-label="Engagement name"
            spellCheck={false}
          />

          <div className="hp-eng-meta">
            <span className="hp-eng-goal">{session.goal}</span>
            {session.target_type && (
              <span className="hp-chip hp-chip-dim">{session.target_type}</span>
            )}
          </div>

          <div className="hp-eng-progress">
            <div className="hp-eng-bar">
              <div
                className="hp-eng-bar-fill"
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="hp-eng-progress-txt">
              {checked} / {total} done
              {total > 0 && checked === total ? " · complete ✓" : ""}
            </span>
          </div>
        </header>

        <ol className="hp-ap-phases hp-eng-phases">
          {session.path.phases.map((ph, pi) => (
            <li className="hp-ap-phase" key={ph.phase}>
              <div className="hp-ap-phase-head">
                <span className="hp-ap-phase-n">{pi + 1}</span>
                <h2 className="hp-ap-phase-label">{ph.label}</h2>
                <span className="hp-ap-phase-count">
                  {ph.steps.filter((s) => state[s.id]?.checked).length}/
                  {ph.steps.length}
                </span>
              </div>
              <div className="hp-ap-steps">
                {ph.steps.map((step) => (
                  <StepCard
                    key={step.id}
                    step={step}
                    checked={state[step.id]?.checked ?? false}
                    initialResult={state[step.id]?.result_text ?? ""}
                    onToggle={() => toggle(step.id)}
                    onSaveResult={(text) => saveResult(step.id, text)}
                  />
                ))}
              </div>
            </li>
          ))}
        </ol>
      </div>
    </PageShell>
  );
}

/** One engagement step: checkbox, why, commands, technique link, results box. */
function StepCard({
  step,
  checked,
  initialResult,
  onToggle,
  onSaveResult,
}: {
  step: EngagementStep;
  checked: boolean;
  initialResult: string;
  onToggle: () => void;
  onSaveResult: (text: string) => Promise<StepState>;
}) {
  const [notesOpen, setNotesOpen] = useState(!!initialResult);

  return (
    <article className={`hp-ap-step hp-eng-step${checked ? " is-done" : ""}`}>
      <div className="hp-eng-step-top">
        <button
          type="button"
          role="checkbox"
          aria-checked={checked}
          className={`hp-eng-check${checked ? " is-on" : ""}`}
          onClick={onToggle}
          aria-label={checked ? "Mark step incomplete" : "Mark step complete"}
        >
          {checked ? "✓" : ""}
        </button>

        <div className="hp-eng-step-main">
          <div className="hp-ap-step-head">
            <span className="hp-ap-step-id">{step.id}</span>
            <h3 className="hp-ap-step-title">{step.title}</h3>
            <Link href={`/entry/${step.entry_id}`} className="hp-ap-step-link">
              technique →
            </Link>
          </div>

          {step.why && <p className="hp-ap-why">{step.why}</p>}

          {step.commands.length > 0 ? (
            step.commands.map((c, i) => (
              <div className="hp-code" key={i}>
                <div className="hp-code-bar">
                  <span className="hp-code-lang">{c.lang || "sh"}</span>
                  {c.copyable !== false && <CopyButton text={c.cmd} />}
                </div>
                <pre className="hp-code-pre">
                  <code>{c.cmd}</code>
                </pre>
              </div>
            ))
          ) : (
            <div className="hp-ap-nocode">
              No commands on this entry —{" "}
              <Link href={`/entry/${step.entry_id}`}>open the full technique</Link>
              .
            </div>
          )}

          <ResultBox
            open={notesOpen}
            onToggleOpen={() => setNotesOpen((o) => !o)}
            initial={initialResult}
            onSave={onSaveResult}
          />
        </div>
      </div>
    </article>
  );
}

type SaveState = "idle" | "typing" | "saving" | "saved" | "error";

/** Collapsible results/notes textarea that debounce-autosaves as you type. */
function ResultBox({
  open,
  onToggleOpen,
  initial,
  onSave,
}: {
  open: boolean;
  onToggleOpen: () => void;
  initial: string;
  onSave: (text: string) => Promise<StepState>;
}) {
  const [text, setText] = useState(initial);
  const [status, setStatus] = useState<SaveState>("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastSaved = useRef(initial);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    []
  );

  const onChange = (value: string) => {
    setText(value);
    setStatus("typing");
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      if (value === lastSaved.current) {
        setStatus("idle");
        return;
      }
      setStatus("saving");
      onSave(value)
        .then(() => {
          lastSaved.current = value;
          setStatus("saved");
          setTimeout(
            () => setStatus((s) => (s === "saved" ? "idle" : s)),
            1400
          );
        })
        .catch(() => setStatus("error"));
    }, RESULT_DEBOUNCE_MS);
  };

  const label =
    status === "saving"
      ? "saving…"
      : status === "saved"
        ? "✓ saved"
        : status === "error"
          ? "save failed"
          : status === "typing"
            ? "unsaved…"
            : "";

  return (
    <div className="hp-eng-notes">
      <button
        type="button"
        className="hp-eng-notes-toggle"
        onClick={onToggleOpen}
        aria-expanded={open}
      >
        <span className="hp-eng-notes-caret">{open ? "▾" : "▸"}</span>
        results / notes
        {!open && text.trim() ? (
          <span className="hp-eng-notes-has">· has notes</span>
        ) : null}
      </button>

      {open && (
        <div className="hp-eng-notes-body">
          <textarea
            className="hp-eng-textarea"
            value={text}
            onChange={(e) => onChange(e.target.value)}
            placeholder="Paste output, creds, hashes, findings… autosaves as you type."
            spellCheck={false}
            rows={4}
          />
          <span
            className={`hp-eng-savestate${
              status === "error" ? " is-err" : ""
            }`}
          >
            {label}
          </span>
        </div>
      )}
    </div>
  );
}
