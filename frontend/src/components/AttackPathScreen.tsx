"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import { LLMSettingsModal } from "./LLMSettingsModal";
import { ModelBadge } from "./ModelBadge";
import { TargetTypeChips } from "./TargetTypeChips";
import { ComposingLoader } from "./ComposingLoader";
import { DetectionDisclosure } from "./DetectionPanel";
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
  const [scopeText, setScopeText] = useState("");
  const [scopeOpen, setScopeOpen] = useState(false);

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

      composeAttackPath(g, targetType, scopeText.trim() || null, ctrl.signal)
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
    [goal, targetType, scopeText, loading]
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
            <TargetTypeChips
              value={targetType}
              onChange={setTargetType}
              disabled={loading}
            />

            <button
              type="submit"
              className="hp-ap-submit"
              disabled={loading || goal.trim().length < 3}
            >
              {loading ? "composing…" : "compose path →"}
            </button>
          </div>

          <div className="hp-ap-scope">
            <button
              type="button"
              className="hp-ap-scope-toggle"
              aria-expanded={scopeOpen}
              onClick={() => setScopeOpen((o) => !o)}
              disabled={loading}
            >
              <span className="hp-ap-scope-sign" aria-hidden>
                {scopeOpen ? "−" : "+"}
              </span>
              Scope / Rules of Engagement{" "}
              <span className="hp-ap-scope-opt">(optional)</span>
              {!scopeOpen && scopeText.trim() && (
                <span className="hp-ap-scope-dot" title="scope text entered" />
              )}
            </button>
            {scopeOpen && (
              <textarea
                className="hp-ap-scope-text"
                value={scopeText}
                onChange={(e) => setScopeText(e.target.value)}
                placeholder={
                  "Paste in-scope / out-of-scope hosts and paths, or the program’s Rules of Engagement.\n" +
                  "The profiler uses it to prioritise the right bug classes and drop out-of-scope steps."
                }
                rows={5}
                spellCheck={false}
                disabled={loading}
                aria-label="Scope / Rules of Engagement"
              />
            )}
          </div>
        </form>

        {loading && <ComposingLoader config={config} />}

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
                {result.origin === "writeup" ? (
                  <span className="hp-ap-model hp-ap-model-wu">
                    built from <b>your writeup</b>
                  </span>
                ) : (
                  <span className="hp-ap-model">
                    composed by <b>{result.model_used}</b>
                    {result.provider === "ollama" ? (
                      <span className="hp-ap-local"> · local</span>
                    ) : (
                      <span className="hp-ap-local"> · {result.provider}</span>
                    )}
                  </span>
                )}
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

            {result.origin === "writeup" && (
              <div className="hp-ap-origin">
                <span className="hp-ap-origin-ic">▤</span>
                <div className="hp-ap-origin-txt">
                  <b>
                    {result.origin_label ??
                      `from your writeup${
                        result.box_writeup ? `: ${result.box_writeup.title}` : ""
                      }`}
                  </b>
                  <span className="hp-ap-origin-sub">
                    These steps are your own recorded walkthrough for this box —
                    trusted, in order.
                  </span>
                  {result.origin_note && (
                    <span className="hp-ap-origin-warn">⚠ {result.origin_note}</span>
                  )}
                </div>
                {result.box_writeup && (
                  <Link
                    href={`/entry/${encodeURIComponent(result.box_writeup.id)}`}
                    className="hp-ap-origin-go"
                  >
                    open writeup →
                  </Link>
                )}
              </div>
            )}

            {result.origin !== "writeup" && result.box_writeup && (
              <Link
                href={`/entry/${encodeURIComponent(result.box_writeup.id)}`}
                className="hp-ap-writeup"
              >
                <span className="hp-ap-writeup-ic">▤</span>
                <span className="hp-ap-writeup-txt">
                  Full writeup available for this box —{" "}
                  <b>{result.box_writeup.title}</b>
                  {result.box_writeup.tier === 1 && (
                    <span className="hp-ap-writeup-mine"> · your notes</span>
                  )}
                </span>
                <span className="hp-ap-writeup-go">open →</span>
              </Link>
            )}

            {/* CHANNEL 2 — what the planner READ to reason with. Not steps, and
                not a step's source: the grounded/ai_suggested labels below are
                unchanged by this. It's here so the reasoning is inspectable. */}
            {!!result.context_sources?.length && (
              <div className="hp-ap-informed">
                <span className="hp-ap-informed-lbl">informed by</span>
                {result.context_sources.map((src, i) => (
                  <span key={src.id}>
                    {i > 0 && <span aria-hidden="true">· </span>}
                    <Link
                      href={`/entry/${encodeURIComponent(src.id)}`}
                      className="hp-ap-informed-src"
                    >
                      {src.title}
                    </Link>{" "}
                    <span className="hp-ap-informed-kind">{src.kind}</span>
                  </span>
                ))}
                <span className="hp-ap-informed-kind">
                  read as background — never a step
                </span>
              </div>
            )}

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

            {(result.profile?.target_class ||
              (result.profile?.priority_bug_classes?.length ?? 0) > 0 ||
              result.scoped) && (
              <div className="hp-ap-profile">
                <span className="hp-ap-profile-label">why these steps</span>
                {result.profile?.target_class && (
                  <span className="hp-ap-profile-class">
                    {result.profile.target_class}
                  </span>
                )}
                {result.profile?.priority_bug_classes?.map((b) => (
                  <span className="hp-ap-profile-chip" key={b}>
                    {b}
                  </span>
                ))}
                {result.scoped && (
                  <span
                    className="hp-ap-scoped-badge"
                    title="One or more steps were dropped for touching an out-of-scope path/host from your pasted scope."
                  >
                    ✓ scoped
                  </span>
                )}
              </div>
            )}

            {/* THE HONESTY BANNER. A composed path is built from the KB's commands, which
                were written against the KB author's target. Before this, a plan where none
                of them had been adapted looked exactly like one where all of them had. The
                three states are deliberately distinct — "unchecked" must never read as
                "clean". */}
            {(result.commands_total ?? 0) > 0 &&
              (!result.scope_checked ? (
                <p className="hp-ap-runnable">
                  <span className="hp-ap-runnable-lead">commands not checked</span>
                  no scope was pasted, so there was nothing to check these{" "}
                  {result.commands_total} commands against. Paste your scope to have every
                  one of them judged against it.
                </p>
              ) : (result.commands_unrunnable ?? 0) > 0 ? (
                <p className="hp-ap-runnable hp-ap-runnable-warn">
                  {/* {" "} explicitly: JSX drops the space between an expression and the
                      text after it when the two are split across a line break, and it
                      rendered as "16commands" in the browser. */}
                  <span className="hp-ap-runnable-lead">
                    {result.commands_unrunnable} of {result.commands_total}
                    {" commands won’t run as written"}
                  </span>
                  they point outside your scope, or name no target at all. Each one says
                  which, below. The rest name a host in scope.
                </p>
              ) : (
                <p className="hp-ap-runnable hp-ap-runnable-ok">
                  <span className="hp-ap-runnable-lead">
                    all {result.commands_total} commands name a host in scope
                  </span>
                  {result.target_source === "scope" && result.target && (
                    <>
                      target <code>{result.target}</code> was taken from your scope —
                      HackPit chose it, so check it is the one you meant.
                    </>
                  )}
                </p>
              ))}

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
          <ModelBadge
            config={config}
            onOpenSettings={() => setSettingsOpen(true)}
          />
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

/**
 * One step. Grounded/writeup steps (ai_suggested falsy) cite a KB entry and
 * reuse its real commands. AI-suggested steps carry no entry link and are tinted
 * with a "verify" badge — the commands are the model's own, unverified.
 */
function StepCard({ step }: { step: AttackStep }) {
  const ai = step.ai_suggested === true;
  const wu = step.from_writeup === true;
  return (
    <article
      className={`hp-ap-step${ai ? " hp-ap-step-ai" : ""}${
        wu ? " hp-ap-step-wu" : ""
      }`}
      id={step.id}
    >
      <div className="hp-ap-step-head">
        <span className="hp-ap-step-id">{step.id}</span>
        <h3 className="hp-ap-step-title">{step.title}</h3>
        {wu && (
          <span
            className="hp-ap-wu-chip"
            title="From your own writeup for this box — trusted, in order."
          >
            writeup
          </span>
        )}
        {ai ? (
          <span
            className="hp-ap-ai-badge"
            title="Not from your knowledge base — general-knowledge suggestion; verify before running."
          >
            AI-suggested · verify
          </span>
        ) : (
          step.entry_id && (
            <Link
              href={`/entry/${encodeURIComponent(step.entry_id)}`}
              className="hp-ap-step-link"
            >
              {wu ? "writeup →" : "technique →"}
            </Link>
          )
        )}
      </div>

      {step.why && <p className="hp-ap-why">{step.why}</p>}

      {step.target_adaptation && (
        <p className="hp-ap-adapt">
          <span className="hp-ap-adapt-lead">→ for this target</span>
          {step.target_adaptation}
        </p>
      )}

      {step.foreign_refs && step.foreign_refs.length > 0 && (
        <p className="hp-ap-foreign">
          <span className="hp-ap-foreign-lead">⚠ not your target</span>
          references{" "}
          {step.foreign_refs.map((ref, i) => (
            <span key={ref}>
              {i > 0 && ", "}
              <code className="hp-ap-foreign-ref">«{ref}»</code>
            </span>
          ))}{" "}
          — this command was written for another environment; verify or replace it for your
          target before running it.
        </p>
      )}

      {step.commands.length > 0 ? (
        step.commands.map((c, i) => (
          <div
            className={`hp-code${c.runnable === false ? " hp-code-unrunnable" : ""}`}
            key={i}
          >
            <div className="hp-code-bar">
              <span className="hp-code-lang">{c.lang || "sh"}</span>
              {c.runnable === false && (
                <span className="hp-code-flag">won&rsquo;t run as written</span>
              )}
              {c.copyable !== false && <CopyButton text={c.cmd} />}
            </div>
            <pre className="hp-code-pre">
              <code>{c.cmd}</code>
            </pre>
            {/* THE SCOPE CHECK. Shown under the command it judges, never as a page-level
                summary the eye skips: this is the difference between a plan that is ready
                and one that only looks ready. It refuses nothing — the executor's
                target/scope lock is what actually stops an off-target command. */}
            {c.runnable === false && c.unrunnable_reason && (
              <p className="hp-code-why">{c.unrunnable_reason}</p>
            )}
          </div>
        ))
      ) : ai ? (
        <div className="hp-ap-nocode">
          No commands suggested — verify this step against a trusted source.
        </div>
      ) : (
        <div className="hp-ap-nocode">
          No commands on this entry —{" "}
          <Link href={`/entry/${encodeURIComponent(step.entry_id)}`}>
            open the full technique
          </Link>
          .
        </div>
      )}

      {(step.on_success || step.on_blocked) && (
        <div className="hp-ap-branches">
          {step.on_success && (
            <p className="hp-ap-branch hp-ap-branch-ok">
              <span className="hp-ap-branch-lead">if it works →</span>
              <Branch text={step.on_success} />
            </p>
          )}
          {step.on_blocked && (
            <p className="hp-ap-branch hp-ap-branch-blocked">
              <span className="hp-ap-branch-lead">if blocked →</span>
              <Branch text={step.on_blocked} />
            </p>
          )}
        </div>
      )}

      {/* The defender's view of this step: ATT&CK tag, telemetry, the rule that would fire,
          and how loud it is. Annotation only — it never alters the step above. */}
      {step.commands.length > 0 && (
        <div className="hp-det-row">
          <DetectionDisclosure
            tag={step.attck}
            source={{ kind: "step", step }}
            heading={`If this step ran: ${step.title}`}
          />
        </div>
      )}
    </article>
  );
}

// A step id embedded in a branch hint (e.g. "pivot to privesc-2") becomes an
// in-page jump link to that step card; everything else renders as plain prose.
const STEP_ID_RE =
  /\b(recon|enumeration|exploitation|privesc|post-exploitation)-\d+\b/g;

function Branch({ text }: { text: string }) {
  const parts: React.ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(STEP_ID_RE)) {
    const id = m[0];
    const start = m.index ?? 0;
    if (start > last) parts.push(text.slice(last, start));
    parts.push(
      <a
        key={`${id}-${start}`}
        href={`#${id}`}
        className="hp-ap-branch-jump"
        onClick={(e) => {
          e.preventDefault();
          document
            .getElementById(id)
            ?.scrollIntoView({ behavior: "smooth", block: "center" });
        }}
      >
        {id}
      </a>
    );
    last = start + id.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return <span className="hp-ap-branch-text">{parts}</span>;
}
