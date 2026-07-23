"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { CopyButton } from "./CopyButton";
import type { AttackPath, AttackPhase, AttackStep } from "@/lib/api";

/** The five canonical phases, in kill-chain order — the route's fixed stations. */
const CANON: { key: string; label: string }[] = [
  { key: "recon", label: "Recon" },
  { key: "enumeration", label: "Enumeration" },
  { key: "exploitation", label: "Exploitation" },
  { key: "privesc", label: "Privilege Escalation" },
  { key: "post-exploitation", label: "Post-Exploitation" },
];

type Station = {
  key: string;
  label: string;
  index: number; // 1-based station number
  startIndex: number; // global ignite index of this station's first node
  steps: AttackStep[];
  present: boolean; // false = phase skipped for this path (dim station)
};

/** Bucket the composed path into the five canonical stations, in order, with a
 *  precomputed global start index per station (so the ignite sequence needs no
 *  render-time mutation). */
function toStations(path: AttackPath): Station[] {
  const byKey = new Map<string, AttackPhase>();
  for (const p of path.phases) byKey.set(p.phase, p);
  let running = 0;
  return CANON.map((c, i) => {
    const p = byKey.get(c.key);
    const steps = p?.steps ?? [];
    const station: Station = {
      key: c.key,
      label: p?.label || c.label,
      index: i + 1,
      startIndex: running,
      steps,
      present: !!p && steps.length > 0,
    };
    running += steps.length;
    return station;
  });
}

function isGrounded(step: AttackStep): boolean {
  return step.ai_suggested !== true;
}

/**
 * The attack-map centerpiece — a composed attack-path rendered as a lit
 * kill-chain route. Five phase stations run down a spine; each step is a node
 * that sits on the route (solid amber = grounded in the KB, dashed/dim =
 * ai_suggested / unverified). on_success / on_blocked hints render as branch
 * forks. Clicking a node opens its detail. `litCount` (used by the ignite
 * animation in M2.2) caps how many nodes are lit; undefined = all lit.
 */
export function CockpitAttackMap({
  path,
  litCount,
}: {
  path: AttackPath;
  litCount?: number;
}) {
  const stations = useMemo(() => toStations(path), [path]);
  const [selected, setSelected] = useState<{ step: AttackStep; phase: string } | null>(
    null
  );

  const profile = path.profile;

  return (
    <div className="hp-cm">
      {/* "why these steps" HUD */}
      <div className="hp-cm-hud">
        <div className="hp-cm-hud-main">
          <span className="hp-cm-hud-eyebrow">kill chain</span>
          <span className="hp-cm-hud-goal">{path.goal}</span>
        </div>
        {profile?.target_class && (
          <div className="hp-cm-hud-why">
            <span className="hp-cm-hud-class">{profile.target_class}</span>
            {profile.priority_bug_classes?.length > 0 && (
              <span className="hp-cm-hud-chips">
                {profile.priority_bug_classes.slice(0, 5).map((c) => (
                  <span key={c} className="hp-cm-hud-chip">
                    {c}
                  </span>
                ))}
              </span>
            )}
          </div>
        )}
      </div>

      {/* the route */}
      <ol className="hp-cm-route">
        {stations.map((st) => (
          <li
            key={st.key}
            className={`hp-cm-station${st.present ? "" : " is-skipped"}`}
          >
            <div className="hp-cm-marker" aria-hidden>
              <span className="hp-cm-num">
                {String(st.index).padStart(2, "0")}
              </span>
              <span className="hp-cm-dot" />
            </div>

            <div className="hp-cm-phase">
              <div className="hp-cm-phase-head">
                <h3 className="hp-cm-phase-label">{st.label}</h3>
                <span className="hp-cm-phase-count">
                  {st.present ? `${st.steps.length} step${st.steps.length === 1 ? "" : "s"}` : "not on this path"}
                </span>
              </div>

              {st.present && (
                <div className="hp-cm-nodes">
                  {st.steps.map((step, localIdx) => {
                    const idx = st.startIndex + localIdx;
                    const lit = litCount === undefined || idx < litCount;
                    const grounded = isGrounded(step);
                    return (
                      <button
                        key={step.id}
                        type="button"
                        className={`hp-cm-node${grounded ? " is-grounded" : " is-ai"}${
                          lit ? " is-lit" : ""
                        }`}
                        onClick={() => setSelected({ step, phase: st.label })}
                        aria-label={`${step.title} — ${grounded ? "grounded" : "unverified"} step`}
                      >
                        <span className="hp-cm-node-pip" aria-hidden />
                        <span className="hp-cm-node-body">
                          <span className="hp-cm-node-title">{step.title}</span>
                          {!grounded && (
                            <span className="hp-cm-node-tag">unverified</span>
                          )}
                          {step.from_writeup && (
                            <span className="hp-cm-node-tag is-writeup">writeup</span>
                          )}
                        </span>
                        {(step.on_success || step.on_blocked) && (
                          <span className="hp-cm-node-forks" aria-hidden>
                            {step.on_success && <span className="hp-cm-fork is-success">↳ success</span>}
                            {step.on_blocked && <span className="hp-cm-fork is-blocked">↳ blocked</span>}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          </li>
        ))}
      </ol>

      {selected && (
        <NodeDetail
          step={selected.step}
          phase={selected.phase}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

/** Slide-in detail for one node: why, adaptation, branches, commands. */
function NodeDetail({
  step,
  phase,
  onClose,
}: {
  step: AttackStep;
  phase: string;
  onClose: () => void;
}) {
  const grounded = isGrounded(step);
  return (
    <div className="hp-cm-detail-scrim" onClick={onClose} role="presentation">
      <aside
        className="hp-cm-detail"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label={`${step.title} detail`}
      >
        <button type="button" className="hp-cm-detail-close" onClick={onClose} aria-label="Close">
          ✕
        </button>
        <div className="hp-cm-detail-eyebrow">
          {phase}
          <span className={`hp-cm-detail-badge${grounded ? " is-grounded" : " is-ai"}`}>
            {grounded ? "grounded" : "unverified · verify"}
          </span>
        </div>
        <h2 className="hp-cm-detail-title">{step.title}</h2>

        {step.why && <p className="hp-cm-detail-why">{step.why}</p>}

        {step.target_adaptation && (
          <div className="hp-cm-detail-adapt">
            <span className="hp-cm-detail-adapt-tag">for this target</span>
            {step.target_adaptation}
          </div>
        )}

        {(step.on_success || step.on_blocked) && (
          <div className="hp-cm-detail-branches">
            {step.on_success && (
              <div className="hp-cm-detail-branch is-success">
                <span>on success</span>
                {step.on_success}
              </div>
            )}
            {step.on_blocked && (
              <div className="hp-cm-detail-branch is-blocked">
                <span>if blocked</span>
                {step.on_blocked}
              </div>
            )}
          </div>
        )}

        {step.commands.length > 0 ? (
          <div className="hp-cm-detail-cmds">
            {step.commands.map((c, i) => (
              <div key={i} className="hp-cm-detail-cmd">
                <code>{c.cmd}</code>
                {c.copyable !== false && <CopyButton text={c.cmd} />}
              </div>
            ))}
          </div>
        ) : (
          <p className="hp-cm-detail-nocmd">
            No commands — verify this step against a trusted source.
          </p>
        )}

        {step.entry_id && (
          <Link className="hp-cm-detail-entry" href={`/entry/${encodeURIComponent(step.entry_id)}`}>
            open technique →
          </Link>
        )}
      </aside>
    </div>
  );
}
