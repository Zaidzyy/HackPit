"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ApiError,
  getVRTCategories,
  setSubmission,
  type Session,
  type VRTCategory,
} from "@/lib/api";

/**
 * The bug-bounty SUBMISSION fields: CVSS vector, Bugcrowd VRT category, and the program's
 * published known-issues list.
 *
 * WHY THESE ARE HERE AT ALL. `report.py` has read `session['cvss_vector']` since the
 * bug-bounty template shipped, and nothing ever wrote it — no column, no endpoint, no
 * control. The CVSS calculator this project verified against six reference vectors could not
 * appear in a single real report. This panel is the missing half.
 *
 * THE VRT PRIORITY IS A LOOKUP, NOT A CALCULATION. Bugcrowd triages on the taxonomy, and it
 * genuinely disagrees with CVSS — a stored XSS is P2 whatever its vector works out to.
 * Deriving the priority from the score would produce a confident P-number with no
 * relationship to the taxonomy, in the field a triager reads first. So the category is
 * chosen, and the priority follows from it.
 *
 * KNOWN ISSUES FLAG, THEY NEVER SUPPRESS. At report time each finding is compared against
 * this list and possible matches are surfaced. Nothing is dropped: a false match that
 * silently removed a real finding costs a paid bug and nobody ever learns it happened.
 */

/** The eight CVSS 3.1 base metrics, in vector order, with their allowed values. */
const CVSS_METRICS: { key: string; label: string; opts: [string, string][] }[] = [
  // Labels are kept SHORT because they sit above their select in a wrapping flex row: the
  // full CVSS names ("privileges required", "user interaction") wrap to a second line, which
  // pushes that one select down and breaks the row's alignment. The metric key is shown
  // beside the label anyway, so the long form buys nothing.
  { key: "AV", label: "attack vector",
    opts: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]] },
  { key: "AC", label: "complexity", opts: [["L", "Low"], ["H", "High"]] },
  { key: "PR", label: "privileges", opts: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  { key: "UI", label: "interaction", opts: [["N", "None"], ["R", "Required"]] },
  { key: "S", label: "scope", opts: [["U", "Unchanged"], ["C", "Changed"]] },
  { key: "C", label: "confidentiality", opts: [["H", "High"], ["L", "Low"], ["N", "None"]] },
  { key: "I", label: "integrity", opts: [["H", "High"], ["L", "Low"], ["N", "None"]] },
  { key: "A", label: "availability", opts: [["H", "High"], ["L", "Low"], ["N", "None"]] },
];

type Metrics = Record<string, string>;

const DEFAULT_METRICS: Metrics = {
  AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H",
};

function toVector(m: Metrics): string {
  return "CVSS:3.1/" + CVSS_METRICS.map(({ key }) => `${key}:${m[key]}`).join("/");
}

/** Parse a pasted vector into metrics. Returns null if any base metric is missing/invalid. */
function fromVector(raw: string): Metrics | null {
  const parts: Metrics = {};
  for (const tok of raw.trim().split("/")) {
    const [k, v] = tok.split(":");
    if (k && v) parts[k.trim().toUpperCase()] = v.trim().toUpperCase();
  }
  const out: Metrics = {};
  for (const { key, opts } of CVSS_METRICS) {
    const v = parts[key];
    if (!v || !opts.some(([code]) => code === v)) return null;
    out[key] = v;
  }
  return out;
}

/**
 * CVSS 3.1 base score, computed in the browser purely for the LIVE PREVIEW.
 *
 * The AUTHORITATIVE score is the backend's — `report.py::cvss31_base`, verified against six
 * reference vectors including the roundup edges — and that is what lands in the report. This
 * is the same arithmetic so the operator sees the number while choosing, rather than after
 * generating a report. If the two ever disagree the backend wins by construction: the report
 * never reads this value.
 */
function score(m: Metrics): { score: number; severity: string } {
  const changed = m.S === "C";
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV] ?? 0;
  const AC = { L: 0.77, H: 0.44 }[m.AC] ?? 0;
  const PR = (changed
    ? { N: 0.85, L: 0.68, H: 0.5 }
    : { N: 0.85, L: 0.62, H: 0.27 })[m.PR] ?? 0;
  const UI = { N: 0.85, R: 0.62 }[m.UI] ?? 0;
  const cia = (v: string) => ({ H: 0.56, L: 0.22, N: 0 }[v] ?? 0);
  const iss = 1 - (1 - cia(m.C)) * (1 - cia(m.I)) * (1 - cia(m.A));
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const expl = 8.22 * AV * AC * PR * UI;
  const roundup = (x: number) => Math.ceil(x * 10) / 10;
  const base =
    impact <= 0
      ? 0
      : changed
        ? roundup(Math.min(1.08 * (impact + expl), 10))
        : roundup(Math.min(impact + expl, 10));
  const severity =
    base === 0 ? "None" : base < 4 ? "Low" : base < 7 ? "Medium" : base < 9 ? "High" : "Critical";
  return { score: base, severity };
}

export function SubmissionPanel({
  session,
  onSaved,
}: {
  session: Session;
  onSaved?: (next: Session) => void;
}) {
  const [open, setOpen] = useState(false);
  const [metrics, setMetrics] = useState<Metrics>(
    () => fromVector(session.cvss_vector ?? "") ?? DEFAULT_METRICS
  );
  /** True once the operator has actually chosen a vector — an untouched panel must not
   *  silently save the defaults as if they were a rating. */
  const [hasVector, setHasVector] = useState(!!session.cvss_vector);
  const [paste, setPaste] = useState("");
  const [pasteErr, setPasteErr] = useState<string | null>(null);
  const [vrt, setVrt] = useState(session.vrt_category ?? "");
  const [known, setKnown] = useState(session.known_issues ?? "");
  const [cats, setCats] = useState<VRTCategory[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    let live = true;
    getVRTCategories()
      .then((r) => {
        if (live) setCats(r.categories);
      })
      .catch(() => {
        if (live) setCats([]);
      });
    return () => {
      live = false;
    };
  }, []);

  const vector = useMemo(() => toVector(metrics), [metrics]);
  const computed = useMemo(() => score(metrics), [metrics]);
  const chosen = useMemo(() => cats.find((c) => c.key === vrt) ?? null, [cats, vrt]);

  const applyPaste = useCallback(() => {
    const parsed = fromVector(paste);
    if (!parsed) {
      setPasteErr("not a complete CVSS 3.1 base vector — all eight metrics are needed");
      return;
    }
    setMetrics(parsed);
    setHasVector(true);
    setPaste("");
    setPasteErr(null);
  }, [paste]);

  const save = useCallback(() => {
    setSaving(true);
    setError(null);
    setSaved(false);
    setSubmission(session.id, {
      // An untouched vector saves as "" (clear), not as the defaults — the panel must never
      // invent a 9.8 Critical for an engagement nobody has rated.
      cvss_vector: hasVector ? vector : "",
      vrt_category: vrt,
      known_issues: known,
    })
      .then((next) => {
        setSaved(true);
        onSaved?.(next);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setSaving(false));
  }, [session.id, hasVector, vector, vrt, known, onSaved]);

  const summary = [
    session.cvss_vector ? `CVSS set` : null,
    session.vrt_category ? `VRT ${session.vrt_category}` : null,
    session.known_issues ? `known issues pasted` : null,
  ].filter(Boolean);

  return (
    <section className="hp-tn-card hp-sub">
      <button
        type="button"
        className="hp-sub-toggle"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <span className="hp-tn-cardhead">submission details</span>
        <span className="hp-sub-summary">
          {summary.length ? summary.join(" · ") : "nothing set — optional"}
        </span>
        <span className="hp-sub-chev">{open ? "−" : "+"}</span>
      </button>

      {open && (
        <>
          <div className="hp-tn-cardsub">
            What the bug-bounty report renders alongside the finding. All optional; a field
            left empty is simply absent from the report.
          </div>

          {/* ---- CVSS -------------------------------------------------------- */}
          <div className="hp-sub-group">
            <div className="hp-tn-olhint">cvss 3.1 vector</div>
            <div className="hp-tn-form">
              <input
                className="hp-tn-input"
                value={paste}
                onChange={(e) => setPaste(e.target.value)}
                placeholder="paste a vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                aria-label="Paste a CVSS vector"
              />
              <button
                type="button"
                className="hp-tn-start"
                onClick={applyPaste}
                disabled={!paste.trim()}
              >
                apply
              </button>
            </div>
            {pasteErr && <p className="hp-tn-note hp-tn-note-warn">{pasteErr}</p>}

            <div className="hp-sub-metrics">
              {CVSS_METRICS.map(({ key, label, opts }) => (
                <label className="hp-sub-metric" key={key}>
                  <span className="hp-tn-olhint">
                    {key} · {label}
                  </span>
                  <select
                    value={metrics[key]}
                    onChange={(e) => {
                      setMetrics((m) => ({ ...m, [key]: e.target.value }));
                      setHasVector(true);
                    }}
                    aria-label={label}
                  >
                    {opts.map(([code, name]) => (
                      <option key={code} value={code}>
                        {name}
                      </option>
                    ))}
                  </select>
                </label>
              ))}
            </div>

            <p className={`hp-sub-score${hasVector ? " is-set" : ""}`}>
              {hasVector ? (
                <>
                  <b>
                    {computed.score.toFixed(1)} {computed.severity}
                  </b>
                  <code>{vector}</code>
                </>
              ) : (
                <span className="hp-tn-note">
                  No vector set. Paste one or change a metric above — until then the report
                  carries no CVSS block at all, which is honest rather than a default score.
                </span>
              )}
            </p>
          </div>

          {/* ---- VRT --------------------------------------------------------- */}
          <div className="hp-sub-group">
            <div className="hp-tn-olhint">bugcrowd vrt category</div>
            <div className="hp-tn-form">
              <select
                className="hp-tn-input"
                value={vrt}
                onChange={(e) => setVrt(e.target.value)}
                aria-label="VRT category"
              >
                <option value="">— none —</option>
                {cats.map((c) => (
                  <option key={c.key} value={c.key}>
                    {c.priority} · {c.key} — {c.category}
                  </option>
                ))}
              </select>
            </div>
            <p className="hp-tn-note">
              {chosen ? (
                <>
                  <b>{chosen.priority}</b> — {chosen.meaning}. A LOOKUP on the category, never
                  derived from the CVSS score: the two genuinely disagree, and a triager acts
                  on this one.
                </>
              ) : (
                <>
                  A curated subset of the Bugcrowd VRT at its default priorities. Not the full
                  taxonomy — the program&rsquo;s own brief overrides it.
                </>
              )}
            </p>
          </div>

          {/* ---- known issues ------------------------------------------------ */}
          <div className="hp-sub-group">
            <div className="hp-tn-olhint">known issues, from the program brief</div>
            <textarea
              className="hp-sub-known"
              value={known}
              onChange={(e) => setKnown(e.target.value)}
              rows={5}
              placeholder={
                "One per line, pasted verbatim from the scope table. e.g.\n" +
                "- Missing SPF/DMARC records on non-mail domains\n" +
                "- Self-XSS in the profile bio field"
              }
              aria-label="Known issues"
            />
            <p className="hp-tn-note">
              At report time every finding is compared against this and possible matches are
              <b> flagged</b>. Nothing is ever dropped — a false match that silently removed a
              real finding would cost far more than a warning you dismiss.
            </p>
          </div>

          {error && <div className="hp-tn-error">{error}</div>}

          <div className="hp-tn-actions">
            <span className="hp-tn-actions-label">act</span>
            <button type="button" className="hp-tn-start" onClick={save} disabled={saving}>
              {saving ? "saving…" : "save submission details"}
            </button>
            {saved && !saving && <span className="hp-sub-ok">saved</span>}
          </div>
        </>
      )}
    </section>
  );
}
