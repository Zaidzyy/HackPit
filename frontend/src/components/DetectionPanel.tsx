"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  detectionFootprint,
  detectionFootprintRun,
  detectionFootprintStep,
  type AttackStep,
  type DetectionFootprint,
  type DetectionTag,
  type Loudness,
} from "@/lib/api";

/**
 * The DETECTION FOOTPRINT panel — the purple-team flip of the cockpit.
 *
 * Everywhere else in this app the surface is the OPERATOR's: what to run, what it gets you.
 * This panel is the DEFENDER's: for the same command it shows the MITRE ATT&CK technique and
 * tactic, the telemetry the action generates, the public SigmaHQ rule that would fire on it,
 * and how loud it is.
 *
 * THE LINE — hold it when editing this file. The panel DESCRIBES detection. It does not, and
 * must never, teach evasion. "This is loud / here is the event it throws / here is the rule that
 * catches it" is the whole point. "Here is how to make it quieter / evade that rule / blind that
 * sensor" is out of scope and does not exist here. The loud-vs-quiet rating is an AWARENESS
 * indicator, and on the blue side a COVERAGE one: "quiet" means the defender probably cannot see
 * it yet — a gap for them to close, never a lane for the operator. The backend enforces the same
 * rule in code (detection/resolver.py) and refuses copy that drifts.
 *
 * Read-only throughout: nothing here executes, approves, or changes a gate.
 */

const LOUD_ORDER: Loudness[] = ["quiet", "moderate", "notable", "loud"];

const LOUD_LABEL: Record<Loudness, string> = {
  quiet: "quiet",
  moderate: "moderate",
  notable: "notable",
  loud: "loud",
};

export type DetectionSource =
  | { kind: "command"; command: string; args?: string[]; context?: string }
  | { kind: "argv"; argv: string; context?: string }
  | { kind: "step"; step: AttackStep }
  | { kind: "run"; runId: string };

function loadFootprint(
  source: DetectionSource,
  signal: AbortSignal
): Promise<DetectionFootprint> {
  switch (source.kind) {
    case "run":
      return detectionFootprintRun(source.runId, true, signal);
    case "step":
      return detectionFootprintStep(source.step, true, signal);
    case "argv":
      return detectionFootprint(
        { argv: source.argv, context: source.context ?? "" },
        signal
      );
    default:
      return detectionFootprint(
        {
          command: source.command,
          args: source.args ?? [],
          context: source.context ?? "",
        },
        signal
      );
  }
}

/* ------------------------------------------------------------------ *
 *  compact tag — rides on a step row or a recorded run
 * ------------------------------------------------------------------ */

/**
 * The inline ATT&CK chip: technique id(s), the tactic, and a loudness dot. Clicking opens the
 * full drawer.
 *
 * Three states, and the difference matters. A tag OBJECT renders the technique summary. `null`
 * means the curated map was consulted and has no entry — say so honestly ("not mapped"), because
 * unmapped is not the same as untraceable. `undefined` means no tag was computed for this
 * surface yet, so the chip stays neutral and simply offers to open the footprint.
 */
export function DetectionBadge({
  tag,
  onOpen,
  compact = false,
}: {
  tag: DetectionTag | null | undefined;
  onOpen?: () => void;
  compact?: boolean;
}) {
  if (tag === undefined) {
    return (
      <button
        type="button"
        className="hp-det-chip"
        onClick={onOpen}
        title="Show what a defender would see if this ran"
      >
        <span className="hp-det-eye" aria-hidden>
          ◉
        </span>
        detection footprint
      </button>
    );
  }

  if (tag === null) {
    return (
      <button
        type="button"
        className="hp-det-chip is-unmapped"
        onClick={onOpen}
        title="Not in the curated ATT&CK/SigmaHQ map — open the drawer for a model reading. Unmapped is not the same as untraceable."
      >
        <span className="hp-det-dot is-unknown" aria-hidden />
        detection: not mapped
      </button>
    );
  }

  const ids = tag.techniques.map((t) => t.id);
  const shown = compact ? ids.slice(0, 1) : ids.slice(0, 3);
  const tactic = tag.tactics[0];

  return (
    <button
      type="button"
      className={`hp-det-chip is-${tag.loudness}`}
      onClick={onOpen}
      title={`What a defender would see — ${tag.activity || "detection footprint"}. Signal: ${LOUD_LABEL[tag.loudness]}.`}
    >
      <span className={`hp-det-dot is-${tag.loudness}`} aria-hidden />
      <span className="hp-det-chip-ids">{shown.join(" ")}</span>
      {ids.length > shown.length && (
        <span className="hp-det-chip-more">+{ids.length - shown.length}</span>
      )}
      {tactic && !compact && (
        <span className="hp-det-chip-tactic">{tactic.name}</span>
      )}
      {tag.stealth && (
        <span className="hp-det-chip-stealth" title="Maps to a Stealth / Defense-Evasion technique — which has its own detections">
          stealth
        </span>
      )}
      <span className="hp-det-chip-loud">{LOUD_LABEL[tag.loudness]}</span>
    </button>
  );
}

/* ------------------------------------------------------------------ *
 *  the loudness meter
 * ------------------------------------------------------------------ */
function LoudnessMeter({
  level,
  meaning,
  why,
}: {
  level: Loudness | "";
  meaning: string;
  why: string;
}) {
  const idx = LOUD_ORDER.indexOf(level as Loudness);
  return (
    <div className={`hp-det-loud is-${level || "unknown"}`}>
      <div className="hp-det-loud-head">
        <span className="hp-det-loud-label">signal</span>
        <div className="hp-det-loud-bar" role="img" aria-label={`Signal: ${level || "unknown"}`}>
          {LOUD_ORDER.map((l, i) => (
            <span
              key={l}
              className={`hp-det-loud-seg${i <= idx ? " is-on" : ""} is-${level || "unknown"}`}
            />
          ))}
        </div>
        <span className="hp-det-loud-word">{level || "unknown"}</span>
      </div>
      {meaning && <p className="hp-det-loud-meaning">{meaning}</p>}
      {why && <p className="hp-det-loud-why">{why}</p>}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 *  the drawer
 * ------------------------------------------------------------------ */

/**
 * The full "here's what blue sees" drawer for one command / step / run.
 *
 * Fetches on mount (state is set from the promise callback, never in the effect body, so the
 * repo's lint baseline is unaffected). Everything it renders is annotation: no approve button,
 * no command to run, no gate.
 */
export function DetectionDrawer({
  source,
  heading,
  onClose,
}: {
  source: DetectionSource;
  heading?: string;
  onClose?: () => void;
}) {
  const [fp, setFp] = useState<DetectionFootprint | null>(null);
  const [error, setError] = useState<string | null>(null);

  const key =
    source.kind === "run"
      ? `run:${source.runId}`
      : source.kind === "step"
        ? `step:${source.step.id}`
        : source.kind === "argv"
          ? `argv:${source.argv}`
          : `cmd:${source.command} ${(source.args ?? []).join(" ")}`;

  useEffect(() => {
    const ctrl = new AbortController();
    loadFootprint(source, ctrl.signal)
      .then((v) => {
        if (!ctrl.signal.aborted) {
          setFp(v);
          setError(null);
        }
      })
      .catch(() => {
        if (!ctrl.signal.aborted) {
          setFp(null);
          setError("Couldn’t load the detection footprint.");
        }
      });
    return () => ctrl.abort();
    // `key` fingerprints the source; re-fetch when it changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return (
    <motion.section
      className="hp-det"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      aria-label="Detection footprint"
    >
      <div className="hp-det-head">
        <span className="hp-det-kicker">
          <span className="hp-det-eye" aria-hidden>
            ◉
          </span>
          detection footprint · what blue sees
        </span>
        {fp && (
          <span className={fp.grounded ? "hp-det-badge is-grounded" : "hp-det-badge is-ai"}>
            {fp.grounded ? "grounded · ATT&CK + SigmaHQ" : "ai-suggested · verify"}
          </span>
        )}
        {onClose && (
          <button type="button" className="hp-det-x" onClick={onClose} aria-label="Close">
            ✕
          </button>
        )}
      </div>

      {heading && <p className="hp-det-heading">{heading}</p>}

      {!fp && !error && <p className="hp-det-loading">reading the defender’s view…</p>}
      {error && <p className="hp-det-error">{error}</p>}

      {fp && (
        <>
          {fp.argv && <code className="hp-det-argv">{fp.argv}</code>}
          {fp.activity && <p className="hp-det-activity">{fp.activity}</p>}
          {fp.blue_view && <p className="hp-det-blueview">“{fp.blue_view}”</p>}

          <LoudnessMeter
            level={fp.loudness.level}
            meaning={fp.loudness.meaning}
            why={fp.loudness.why}
          />

          {/* ---- ATT&CK ---- */}
          {fp.techniques.length > 0 && (
            <div className="hp-det-block">
              <h4 className="hp-det-h">MITRE ATT&amp;CK</h4>
              <div className="hp-det-tactics">
                {fp.tactics.map((tac) => (
                  <span
                    key={tac.id}
                    className={`hp-det-tactic${
                      tac.id === "TA0005" || tac.id === "TA0112" ? " is-stealth" : ""
                    }`}
                    title={
                      tac.also_known_as
                        ? `${tac.name} (${tac.id}) — formerly “${tac.also_known_as}”`
                        : `${tac.name} (${tac.id})`
                    }
                  >
                    {tac.name}
                    {tac.also_known_as && (
                      <span className="hp-det-tactic-aka"> · aka {tac.also_known_as}</span>
                    )}
                  </span>
                ))}
              </div>
              <ul className="hp-det-techs">
                {fp.techniques.map((t) => (
                  <li
                    key={t.id}
                    className={`hp-det-tech${t.source === "ai_suggested" ? " is-ai" : ""}`}
                  >
                    <a
                      className="hp-det-tech-id"
                      href={t.url}
                      target="_blank"
                      rel="noreferrer"
                      title="Open this technique on attack.mitre.org"
                    >
                      {t.id}
                    </a>
                    <span className="hp-det-tech-name">{t.name}</span>
                    {t.stealth && <span className="hp-det-tech-stealth">stealth</span>}
                    {t.source === "ai_suggested" && (
                      <span className="hp-det-tech-ai">unverified</span>
                    )}
                  </li>
                ))}
              </ul>
              {fp.stealth.present && (
                <p className="hp-det-stealth-note">{fp.stealth.note}</p>
              )}
            </div>
          )}

          {/* ---- telemetry ---- */}
          {fp.telemetry.length > 0 && (
            <div className="hp-det-block">
              <h4 className="hp-det-h">telemetry this generates</h4>
              <ul className="hp-det-telemetry">
                {fp.telemetry.map((t, i) => (
                  <li key={i}>{t}</li>
                ))}
              </ul>
            </div>
          )}

          {/* ---- Sigma ---- */}
          {fp.sigma.length > 0 && (
            <div className="hp-det-block">
              <h4 className="hp-det-h">
                detections that would fire
                <span className="hp-det-h-note"> · SigmaHQ</span>
              </h4>
              <ul className="hp-det-sigma">
                {fp.sigma.map((r) => (
                  <li key={r.id} className="hp-det-rule">
                    <span className={`hp-det-level is-${r.level}`}>{r.level}</span>
                    <a href={r.url} target="_blank" rel="noreferrer" className="hp-det-rule-title">
                      {r.title}
                    </a>
                    <span className="hp-det-rule-id" title="SigmaHQ rule UUID">
                      {r.id.slice(0, 8)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {fp.grounded && fp.sigma.length === 0 && (
            <p className="hp-det-nosigma">
              No SigmaHQ rule in the curated map covers this directly — the telemetry above is
              where a defender would find it.
            </p>
          )}

          {/* ---- argument-level signals ---- */}
          {fp.signals.length > 0 && (
            <div className="hp-det-block">
              <h4 className="hp-det-h">what the arguments change</h4>
              <ul className="hp-det-signals">
                {fp.signals.map((s) => (
                  <li key={s.id} className={`hp-det-signal${s.stealth ? " is-stealth" : ""}`}>
                    <span className="hp-det-signal-label">
                      {s.label}
                      {s.louder && <span className="hp-det-signal-louder">louder</span>}
                    </span>
                    <span className="hp-det-signal-note">{s.note}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {fp.why && <p className="hp-det-why">{fp.why}</p>}

          <p className="hp-det-foot">
            This describes the footprint from the defender’s side — the technique, the telemetry
            and the rule that catches it. It is not evasion guidance, and there is no “make this
            quieter” here by design.
            {fp.sources?.attack && (
              <span className="hp-det-attr">
                {" "}
                Sources: {fp.sources.attack}; {fp.sources.sigma}.
              </span>
            )}
          </p>
        </>
      )}
    </motion.section>
  );
}

/**
 * Badge + drawer together, with the open/closed state handled locally. This is what most
 * callers want: a chip on the row that expands into the full defender's view underneath.
 */
export function DetectionDisclosure({
  tag,
  source,
  heading,
  compact,
}: {
  /** Omit entirely when no tag has been computed for this surface (see DetectionBadge). */
  tag?: DetectionTag | null;
  source: DetectionSource;
  heading?: string;
  compact?: boolean;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <DetectionBadge tag={tag} compact={compact} onOpen={() => setOpen((o) => !o)} />
      {open && (
        <DetectionDrawer source={source} heading={heading} onClose={() => setOpen(false)} />
      )}
    </>
  );
}
