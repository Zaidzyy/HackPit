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

/** The defender's view. Rendered on every preview and every result, never hidden. */
function FootprintPanel({ fp }: { fp: EvasionFootprint }) {
  return (
    <section className="rounded border border-sky-700/50 bg-sky-950/20 p-3">
      <h3 className="mb-2 text-sm font-semibold text-sky-300">
        What a defender sees
        <span className="ml-2 font-normal text-xs text-sky-500/80">
          (always shown — this cannot be turned off)
        </span>
      </h3>
      <dl className="space-y-2 text-sm">
        <div>
          <dt className="text-xs uppercase tracking-wide text-slate-400">Activity</dt>
          <dd className="text-slate-200">{fp.activity}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-slate-400">Blue-team view</dt>
          <dd className="text-slate-200">{fp.blue_view}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-slate-400">
            Loudness — {fp.loudness?.level}
          </dt>
          <dd className="text-slate-300">{fp.loudness?.why}</dd>
        </div>
        {fp.telemetry?.length > 0 && (
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-400">Telemetry</dt>
            <dd>
              <ul className="list-disc pl-5 text-slate-300">
                {fp.telemetry.map((t) => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
            </dd>
          </div>
        )}
        {fp.techniques?.length > 0 && (
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-400">ATT&amp;CK</dt>
            <dd className="text-slate-300">
              {fp.techniques.map((t) => `${t.id} ${t.name}`).join(" · ")}
            </dd>
          </div>
        )}
      </dl>
    </section>
  );
}

/** The operator's half. `still_recorded` is the mandatory honesty marker. */
function OpsecPanel({ note }: { note: EvasionOpsecNote }) {
  return (
    <section className="rounded border border-amber-700/50 bg-amber-950/20 p-3">
      <h3 className="mb-2 text-sm font-semibold text-amber-300">Tradecraft — and its limits</h3>
      <dl className="space-y-2 text-sm">
        <div>
          <dt className="text-xs uppercase tracking-wide text-slate-400">Loud because</dt>
          <dd className="text-slate-200">{note.loud_because}</dd>
        </div>
        {note.quieter?.length > 0 && (
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-400">Quieter</dt>
            <dd>
              <ul className="list-disc pl-5 text-slate-300">
                {note.quieter.map((q) => (
                  <li key={q}>{q}</li>
                ))}
              </ul>
            </dd>
          </div>
        )}
        <div className="rounded border border-amber-600/60 bg-amber-900/30 p-2">
          <dt className="text-xs font-semibold uppercase tracking-wide text-amber-200">
            Still recorded
          </dt>
          <dd className="text-amber-50">{note.still_recorded}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-slate-400">Tradeoff</dt>
          <dd className="text-slate-300">{note.tradeoff}</dd>
        </div>
      </dl>
    </section>
  );
}

export function EvasionScreen() {
  const [techniques, setTechniques] = useState<string[]>([]);
  const [technique, setTechnique] = useState("donut-pack");
  const [payloadPath, setPayloadPath] = useState("");
  const [targetOs, setTargetOs] = useState("windows");
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
      target_os: targetOs,
      techniques: [technique],
      target,
      engagement_id: engagementId || null,
      approved,
      dangerous_ack: ack,
    }),
    [payloadPath, targetOs, technique, target, engagementId]
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
      <div className="space-y-6">
        <p className="max-w-3xl text-sm text-slate-400">
          Builds one artifact and stops. There is no deploy or run control here because the
          backend has no such endpoint. Every build is gated, scope-checked and audited, and
          every result carries the defender&apos;s view of what you just made.
        </p>

        {error && (
          <div className="rounded border border-red-700 bg-red-950/40 p-3 text-sm text-red-200">
            {error}
          </div>
        )}

        <section className="rounded border border-slate-700 bg-slate-900/40 p-4">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Build</h2>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="text-sm">
              <span className="block text-xs uppercase tracking-wide text-slate-400">
                Technique
              </span>
              <select
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2 text-slate-100"
                value={technique}
                onChange={(e) => setTechnique(e.target.value)}
              >
                {(techniques.length ? techniques : [technique]).map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>

            <label className="text-sm">
              <span className="block text-xs uppercase tracking-wide text-slate-400">
                Target OS
              </span>
              <select
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2 text-slate-100"
                value={targetOs}
                onChange={(e) => setTargetOs(e.target.value)}
              >
                <option value="windows">windows</option>
                <option value="linux">linux</option>
              </select>
            </label>

            <label className="text-sm sm:col-span-2">
              <span className="block text-xs uppercase tracking-wide text-slate-400">
                Input payload path {stubTechnique && "(not used by a stub technique)"}
              </span>
              <input
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2 font-mono text-slate-100"
                placeholder="/loot/<engagement>/input.exe"
                value={payloadPath}
                onChange={(e) => setPayloadPath(e.target.value)}
              />
            </label>

            <label className="text-sm">
              <span className="block text-xs uppercase tracking-wide text-slate-400">
                Target (scope-checked)
              </span>
              <input
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2 font-mono text-slate-100"
                placeholder="leave empty in lab"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </label>

            <label className="text-sm">
              <span className="block text-xs uppercase tracking-wide text-slate-400">
                Engagement id
              </span>
              <input
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2 font-mono text-slate-100"
                placeholder="empty = lab"
                value={engagementId}
                onChange={(e) => setEngagementId(e.target.value)}
              />
            </label>
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              className="rounded border border-slate-600 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50"
              onClick={onPreview}
              disabled={busy}
            >
              Preview (runs nothing)
            </button>
          </div>
        </section>

        {preview && (
          <div className="space-y-4">
            {preview.rejected && preview.rejected.gate !== "danger" && (
              <div className="rounded border border-red-700 bg-red-950/40 p-3 text-sm text-red-200">
                <strong>Refused at the {preview.rejected.gate} gate.</strong>{" "}
                {preview.rejected.reason}
              </div>
            )}

            {/* The honest half, rendered BEFORE the confirm button — you see what a defender
                sees before you decide to build it, not afterwards. */}
            <FootprintPanel fp={preview.footprint} />
            <OpsecPanel note={preview.opsec_note} />

            {dangerReason && (
              <div className="rounded border-2 border-red-600 bg-red-950/50 p-4">
                <h3 className="text-sm font-bold uppercase tracking-wide text-red-300">
                  Red confirm
                </h3>
                <p className="mt-1 text-sm text-red-100">{dangerReason}</p>
                <p className="mt-2 text-xs text-red-200/80">
                  This builds an artifact in the sandbox. It is not delivered and not executed.
                </p>
                <button
                  type="button"
                  className="mt-3 rounded bg-red-700 px-3 py-2 text-sm font-semibold text-white hover:bg-red-600 disabled:opacity-50"
                  onClick={onGenerate}
                  disabled={busy}
                >
                  Confirm and build
                </button>
              </div>
            )}
          </div>
        )}

        {result && (
          <div className="space-y-4">
            <section className="rounded border border-slate-700 bg-slate-900/40 p-4">
              <h2 className="mb-2 text-sm font-semibold text-slate-200">Artifact</h2>
              <p className="text-sm text-slate-300">
                <span className="text-slate-500">path </span>
                <code className="font-mono text-slate-100">{result.artifact_path}</code>{" "}
                <CopyButton text={result.artifact_path} />
              </p>
              <p className="mt-1 text-xs text-slate-400">
                mode {result.mode} · exit {String(result.exit_code)} · run {result.run_id}
              </p>
              {result.exit_code !== 0 && result.stderr && (
                <pre className="mt-2 overflow-x-auto rounded bg-slate-950 p-2 text-xs text-amber-200">
                  {result.stderr}
                </pre>
              )}
              {result.stub && (
                <div className="mt-3">
                  <div className="mb-1 flex items-center gap-2 text-xs uppercase tracking-wide text-slate-400">
                    Stub <CopyButton text={result.stub} />
                  </div>
                  <pre className="max-h-72 overflow-auto rounded bg-slate-950 p-2 text-xs text-slate-200">
                    {result.stub}
                  </pre>
                </div>
              )}
            </section>

            {/* Shown again with the result, not just the preview: the artifact and what
                catches it always travel together. */}
            <FootprintPanel fp={result.footprint} />
            <OpsecPanel note={result.opsec_note} />
          </div>
        )}
      </div>
    </PageShell>
  );
}
