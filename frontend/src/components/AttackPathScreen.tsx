"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import { LLMSettingsModal } from "./LLMSettingsModal";
import { ComposingLoader } from "./ComposingLoader";
import {
  ApiError,
  composeAttackPath,
  createSession,
  getLLMConfig,
  type AttackPath,
  type AttackStep,
  type LLMConfig,
} from "@/lib/api";
import { useReducedMotion } from "@/lib/useReducedMotion";

type Chip = { value: string; label: string };

const CHIPS: Chip[] = [
  { value: "pentest", label: "Pentest" },
  { value: "bugbounty", label: "Bug Bounty" },
  { value: "ctf", label: "CTF" },
  { value: "ad", label: "AD" },
];

const PLACEHOLDER =
  "Describe your target — e.g. “HackTheBox Windows AD box”, " +
  "“web app bug bounty”, “Linux privesc”";

/**
 * The guided attack-path surface. A goal (+ optional target chip) is POSTed to
 * /attack-path; the configured LLM composes an ordered, KB-grounded walkthrough
 * which renders as phase sections of copy-ready step cards. Composition is slow
 * on the local model, so the wait gets a cinematic loading state.
 */
export function AttackPathScreen() {
  const reduced = useReducedMotion();

  const [goal, setGoal] = useState("");
  const [targetType, setTargetType] = useState<string | null>(null);

  const [result, setResult] = useState<AttackPath | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [config, setConfig] = useState<LLMConfig | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);

  const router = useRouter();
  const ctrlRef = useRef<AbortController | null>(null);

  // Load current LLM config once (for the "composed by …" line + gear default).
  useEffect(() => {
    const ctrl = new AbortController();
    getLLMConfig(ctrl.signal)
      .then(setConfig)
      .catch(() => setConfig(null));
    return () => ctrl.abort();
  }, []);

  useEffect(() => () => ctrlRef.current?.abort(), []);

  const submit = useCallback(
    (e?: React.FormEvent) => {
      e?.preventDefault();
      const g = goal.trim();
      if (g.length < 3 || loading) return;

      ctrlRef.current?.abort();
      const ctrl = new AbortController();
      ctrlRef.current = ctrl;

      setLoading(true);
      setError(null);
      setResult(null);

      composeAttackPath(g, targetType, ctrl.signal)
        .then((path) => {
          if (ctrl.signal.aborted) return;
          setResult(path);
          setLoading(false);
        })
        .catch((err: unknown) => {
          if (ctrl.signal.aborted) return;
          setLoading(false);
          setError(
            err instanceof ApiError
              ? err.message
              : "Couldn’t compose an attack path."
          );
        });
    },
    [goal, targetType, loading]
  );

  const startEngagement = useCallback(() => {
    if (!result || starting) return;
    setStarting(true);
    setStartError(null);
    createSession(result)
      .then(({ id }) => router.push(`/engagement/${id}`))
      .catch((err: unknown) => {
        setStarting(false);
        setStartError(
          err instanceof ApiError ? err.message : "Couldn’t start the engagement."
        );
      });
  }, [result, starting, router]);

  const providerLabel =
    config?.provider === "ollama" ? "local" : config?.provider;

  return (
    <PageShell
      crumbs={[{ label: "home", href: "/" }, { label: "guided attack paths" }]}
    >
      <div className="hp-ap">
        <header className="hp-ap-head">
          <div className="hp-ap-kicker">generative · grounded in your notes</div>
          <h1 className="hp-ap-title">Guided attack paths</h1>
          <p className="hp-ap-sub">
            Describe the target. Get an ordered recon → exploit → privesc
            walkthrough composed from your own knowledge base — every step cites
            a real technique and reuses its commands.
          </p>
        </header>

        <form className="hp-ap-form" onSubmit={submit}>
          <div className="hp-ap-inputwrap">
            <span className="hp-ap-prompt" aria-hidden>
              &gt;
            </span>
            <input
              className="hp-ap-input"
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              placeholder={PLACEHOLDER}
              spellCheck={false}
              autoComplete="off"
              aria-label="Describe your target"
              disabled={loading}
            />
          </div>

          <div className="hp-ap-controls">
            <div className="hp-ap-chips" role="group" aria-label="Target type">
              {CHIPS.map((c) => (
                <button
                  key={c.value}
                  type="button"
                  className={`hp-ap-chip${
                    targetType === c.value ? " is-on" : ""
                  }`}
                  aria-pressed={targetType === c.value}
                  onClick={() =>
                    setTargetType((t) => (t === c.value ? null : c.value))
                  }
                  disabled={loading}
                >
                  {c.label}
                </button>
              ))}
            </div>

            <button
              type="submit"
              className="hp-ap-submit"
              disabled={loading || goal.trim().length < 3}
            >
              {loading ? "composing…" : "compose path →"}
            </button>
          </div>
        </form>

        {loading && <ComposingLoader model={config?.model} />}

        {error && !loading && (
          <div className="hp-ap-error">
            <p className="hp-note-err">{error}</p>
            <p className="hp-ap-error-hint">
              The default provider is local Ollama — make sure{" "}
              <code>ollama serve</code> is running and{" "}
              <code>{config?.model ?? "qwen3:8b"}</code> is pulled, or{" "}
              <button
                type="button"
                className="hp-ap-linklike"
                onClick={() => setSettingsOpen(true)}
              >
                switch provider
              </button>
              .
            </p>
          </div>
        )}

        {result && !loading && (
          <motion.section
            className="hp-ap-result"
            initial={{ opacity: 0, y: reduced ? 0 : 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: reduced ? 0 : 0.4 }}
          >
            <div className="hp-ap-resulthead">
              <div className="hp-ap-goal">
                <span className="hp-ap-goal-label">attack path for</span>
                <span className="hp-ap-goal-text">{result.goal}</span>
                {result.target ? (
                  <span className="hp-ap-target">
                    target: <b>{result.target}</b>{" "}
                    <span className="hp-ap-target-note">
                      · substituted into every command
                    </span>
                  </span>
                ) : (
                  <span className="hp-ap-target hp-ap-target-none">
                    no target detected in your goal — commands keep their
                    placeholders / example values
                  </span>
                )}
              </div>
              <div className="hp-ap-byline">
                <span className="hp-ap-model">
                  composed by <b>{result.model_used}</b>
                  {result.provider === "ollama" ? (
                    <span className="hp-ap-local"> · local</span>
                  ) : (
                    <span className="hp-ap-local"> · {result.provider}</span>
                  )}
                </span>
                <button
                  type="button"
                  className="hp-ap-gear"
                  aria-label="LLM settings"
                  onClick={() => setSettingsOpen(true)}
                >
                  ⚙
                </button>
              </div>
            </div>

            <div className="hp-ap-startbar">
              <div className="hp-ap-starttext">
                <span className="hp-ap-startbadge">preview</span>
                <p className="hp-ap-starthint">
                  This is a read-only preview.{" "}
                  <b>Start engagement</b> to turn it into a live session — check
                  off steps, paste your results as you go, and generate a report
                  at the end.
                </p>
              </div>
              <button
                type="button"
                className="hp-ap-start"
                onClick={startEngagement}
                disabled={starting}
              >
                {starting ? "starting…" : "Start engagement →"}
              </button>
            </div>
            {startError && (
              <p className="hp-note-err hp-ap-starterr">{startError}</p>
            )}

            <ol className="hp-ap-phases">
              {result.phases.map((ph, pi) => (
                <li className="hp-ap-phase" key={ph.phase}>
                  <div className="hp-ap-phase-head">
                    <span className="hp-ap-phase-n">{pi + 1}</span>
                    <h2 className="hp-ap-phase-label">{ph.label}</h2>
                    <span className="hp-ap-phase-count">
                      {ph.steps.length}{" "}
                      {ph.steps.length === 1 ? "step" : "steps"}
                    </span>
                  </div>
                  <div className="hp-ap-steps">
                    {ph.steps.map((s) => (
                      <StepCard key={s.id} step={s} />
                    ))}
                  </div>
                </li>
              ))}
            </ol>
          </motion.section>
        )}

        {!result && !loading && !error && (
          <div className="hp-ap-hint">
            <span className="hp-ap-hint-dot" />
            {config ? (
              <>
                composed by{" "}
                <b>{config.model}</b>
                <span className="hp-ap-local"> · {providerLabel}</span>{" "}
                <button
                  type="button"
                  className="hp-ap-gear hp-ap-gear-inline"
                  aria-label="LLM settings"
                  onClick={() => setSettingsOpen(true)}
                >
                  ⚙
                </button>
              </>
            ) : (
              <>knowledge-base grounded · local &amp; offline by default</>
            )}
          </div>
        )}
      </div>

      <LLMSettingsModal
        open={settingsOpen}
        config={config}
        onClose={() => setSettingsOpen(false)}
        onSaved={(c) => setConfig(c)}
      />
    </PageShell>
  );
}

/** One grounded step: title, rationale, copyable commands, technique link. */
function StepCard({ step }: { step: AttackStep }) {
  return (
    <article className="hp-ap-step" id={step.id}>
      <div className="hp-ap-step-head">
        <span className="hp-ap-step-id">{step.id}</span>
        <h3 className="hp-ap-step-title">{step.title}</h3>
        <Link
          href={`/entry/${encodeURIComponent(step.entry_id)}`}
          className="hp-ap-step-link"
        >
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
          <Link href={`/entry/${encodeURIComponent(step.entry_id)}`}>
            open the full technique
          </Link>
          .
        </div>
      )}
    </article>
  );
}
