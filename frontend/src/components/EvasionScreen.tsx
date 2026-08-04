"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  generateEvasion,
  listEvasionTechniques,
  previewEvasion,
  type EvasionBody,
  type EvasionFootprint,
  type EvasionOpsecNote,
  type EvasionPreview,
  type EvasionResult,
} from "@/lib/api";

/**
 * AV/EDR evasion artifacts — GENERATE ONLY.
 *
 * This panel builds an artifact and stops. There is no deploy button and no run button,
 * because the backend exposes no such route: delivering an artifact to a host and executing
 * it are separate, separately-approved concerns and they are not built.
 *
 * THE HONEST HALF IS NOT OPTIONAL. Every preview and every result arrives with the blue-team
 * detection footprint and an OPSEC note whose "still recorded" names what catches the
 * technique anyway. Both are rendered ALWAYS — there is no collapse control, no toggle and no
 * setting that hides them. That is the whole reason this surface is allowed to exist: a tool
 * that told you only how to be quieter, and never what still sees you, would be an evasion
 * how-to rather than a purple-team instrument.
 *
 * Generation is a GATED command. Preview first (pure — it evaluates the gates and resolves the
 * footprint without building anything), then approve. Both generators trip the danger
 * heuristic, so a build always comes back as an explicit RED CONFIRM you re-confirm.
 */

/** One labelled fact inside a footprint / opsec panel. */
function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="hp-tn-fact">
      <dt className="hp-tn-olhint">{label}</dt>
      <dd className="hp-tn-factval">{children}</dd>
    </div>
  );
}

/** The defender's view. Rendered on every preview and every result, never hidden. */
function FootprintPanel({ fp }: { fp: EvasionFootprint }) {
  return (
    <section className="hp-tn-card">
      <div className="hp-tn-cardhead">what a defender sees</div>
      <div className="hp-tn-cardsub">always shown — this cannot be turned off</div>
      <dl className="hp-tn-facts">
        <Fact label="activity">{fp.activity}</Fact>
        <Fact label="blue-team view">{fp.blue_view}</Fact>
        <Fact label={`loudness — ${fp.loudness?.level}`}>{fp.loudness?.why}</Fact>
        {fp.telemetry?.length > 0 && (
          <Fact label="telemetry">
            <ul className="hp-tn-bullets">
              {fp.telemetry.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
          </Fact>
        )}
        {fp.techniques?.length > 0 && (
          <Fact label="ATT&CK">
            {fp.techniques.map((t) => `${t.id} ${t.name}`).join(" · ")}
          </Fact>
        )}
      </dl>
    </section>
  );
}

/** The operator's half. `still_recorded` is the mandatory honesty marker. */
function OpsecPanel({ note }: { note: EvasionOpsecNote }) {
  return (
    <section className="hp-tn-card">
      <div className="hp-tn-cardhead">tradecraft — and its limits</div>
      <dl className="hp-tn-facts">
        <Fact label="loud because">{note.loud_because}</Fact>
        {note.quieter?.length > 0 && (
          <Fact label="quieter">
            <ul className="hp-tn-bullets">
              {note.quieter.map((q) => (
                <li key={q}>{q}</li>
              ))}
            </ul>
          </Fact>
        )}
        {/* `still_recorded` keeps its own emphasis after the restyle. It is the sentence that
            makes this surface a purple-team instrument rather than an evasion how-to, and it
            must not flatten into the other facts around it. */}
        <div className="hp-tn-fact hp-tn-fact-loud">
          <dt className="hp-tn-olhint">still recorded</dt>
          <dd className="hp-tn-factval">{note.still_recorded}</dd>
        </div>
        <Fact label="tradeoff">{note.tradeoff}</Fact>
      </dl>
    </section>
  );
}

export function EvasionScreen() {
  const [techniques, setTechniques] = useState<string[]>([]);
  const [technique, setTechnique] = useState("donut-pack");
  const [payloadPath, setPayloadPath] = useState("");
  const [target, setTarget] = useState("");
  const [engagementId, setEngagementId] = useState("");

  const [preview, setPreview] = useState<EvasionPreview | null>(null);
  const [result, setResult] = useState<EvasionResult | null>(null);
  const [dangerReason, setDangerReason] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    listEvasionTechniques()
      .then((r) => {
        if (live) setTechniques(r.techniques.map((t) => t.technique));
      })
      .catch(() => {
        if (live) setTechniques([]);
      });
    return () => {
      live = false;
    };
  }, []);

  const body = useCallback(
    (approved: boolean, ack: boolean): EvasionBody => ({
      payload_path: payloadPath,
      // Exactly one — the backend refuses a list, because a build can only carry the
      // footprint of ONE technique and describing the wrong one is the failure that matters.
      techniques: [technique],
      target,
      engagement_id: engagementId || null,
      approved,
      dangerous_ack: ack,
    }),
    [payloadPath, technique, target, engagementId]
  );

  const onPreview = useCallback(() => {
    setBusy(true);
    setError(null);
    setResult(null);
    setDangerReason(null);
    previewEvasion(body(true, false))
      .then((p) => {
        setPreview(p);
        // A `danger` refusal is the red-confirm asking to be acknowledged, not a failure.
        if (p.rejected?.gate === "danger") setDangerReason(p.rejected.reason);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setBusy(false));
  }, [body]);

  const onGenerate = useCallback(() => {
    setBusy(true);
    setError(null);
    generateEvasion(body(true, true))
      .then((r) => {
        setResult(r);
        setDangerReason(null);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setBusy(false));
  }, [body]);

  const stubTechnique = technique === "amsi-patch" || technique === "etw-blind";

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "evasion" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">donut · shellcode packing · amsi · etw · generate-only</div>
          <h1 className="hp-tn-title">:evasion</h1>
          <p className="hp-tn-sub">
            Builds one artifact and stops. There is no deploy or run control here because the
            backend has no such endpoint. Every build is gated, scope-checked and audited, and
            every result carries the defender&apos;s view of what you just made.
          </p>
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">1 · build</div>
          <div className="hp-tn-form">
            <select
              className="hp-tn-input"
              value={technique}
              onChange={(e) => setTechnique(e.target.value)}
              aria-label="Technique"
            >
              {(techniques.length ? techniques : [technique]).map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <input
              className="hp-tn-input"
              placeholder="/loot/<engagement>/input.exe"
              value={payloadPath}
              onChange={(e) => setPayloadPath(e.target.value)}
              aria-label="Input payload path"
            />
          </div>
          <p className="hp-tn-olhint">
            input payload path{stubTechnique && " — not used by a stub technique"}
          </p>
          <div className="hp-tn-form">
            <input
              className="hp-tn-input"
              placeholder="target (scope-checked) — leave empty in lab"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              aria-label="Target"
            />
            <input
              className="hp-tn-input"
              placeholder="engagement id — empty = lab"
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              aria-label="Engagement id"
            />
          </div>

          <div className="hp-tn-actions">
            <span className="hp-tn-actions-label">act</span>
            <button type="button" className="hp-tn-start" onClick={onPreview} disabled={busy}>
              {busy ? "…" : "preview (runs nothing)"}
            </button>
          </div>
        </section>

        {preview && (
          <>
            {preview.rejected && preview.rejected.gate !== "danger" && (
              <div className="hp-tn-error">
                <strong>Refused at the {preview.rejected.gate} gate.</strong>{" "}
                {preview.rejected.reason}
              </div>
            )}

            {/* The honest half, rendered BEFORE the confirm button — you see what a defender
                sees before you decide to build it, not afterwards. */}
            <FootprintPanel fp={preview.footprint} />
            <OpsecPanel note={preview.opsec_note} />

            {dangerReason && (
              <div className="hp-tn-danger">
                <div className="hp-tn-danger-head">red confirm</div>
                <div className="hp-tn-danger-why">{dangerReason}</div>
                <div className="hp-tn-danger-note">
                  This builds an artifact in the sandbox. It is not delivered and not executed.
                </div>
                <div className="hp-tn-danger-actions">
                  <button
                    type="button"
                    className="hp-tn-danger-go"
                    onClick={onGenerate}
                    disabled={busy}
                  >
                    {busy ? "building…" : "confirm and build"}
                  </button>
                </div>
              </div>
            )}
          </>
        )}

        {result && (
          <>
            <section className="hp-tn-card">
              <div className="hp-tn-cardhead">2 · artifact</div>
              {/* An empty path means the generator failed or timed out and wrote nothing.
                  Offering a copyable path to a file that does not exist reads as success. */}
              {result.artifact_path ? (
                <p className="hp-tn-note">
                  <span className="hp-tn-olhint">path </span>
                  <code>{result.artifact_path}</code> <CopyButton text={result.artifact_path} />
                </p>
              ) : (
                <p className="hp-tn-note hp-tn-note-warn">
                  No artifact was produced — the generator did not complete successfully.
                </p>
              )}
              <p className="hp-tn-olhint">
                mode {result.mode} · exit {String(result.exit_code)} · run {result.run_id}
              </p>
              {result.exit_code !== 0 && result.stderr && (
                <pre className="hp-tn-pre hp-tn-pre-warn">{result.stderr}</pre>
              )}
              {result.stub && (
                <div className="hp-tn-oneliner">
                  <div className="hp-tn-olhint">
                    stub <CopyButton text={result.stub} />
                  </div>
                  <pre className="hp-tn-pre">{result.stub}</pre>
                </div>
              )}
            </section>

            {/* Shown again with the result, not just the preview: the artifact and what
                catches it always travel together. */}
            <FootprintPanel fp={result.footprint} />
            <OpsecPanel note={result.opsec_note} />
          </>
        )}
      </div>
    </PageShell>
  );
}
