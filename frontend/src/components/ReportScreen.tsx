"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { PageShell } from "./PageShell";
import { Markdown } from "./Markdown";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  generateReport,
  getLLMConfig,
  getSession,
  type Session,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useReducedMotion } from "@/lib/useReducedMotion";

const DRAFT_STAGES = [
  "reviewing completed steps",
  "collecting pasted evidence",
  "writing findings & attack narrative",
  "drafting remediation",
  "formatting the report",
];

function slugify(s: string): string {
  return (
    s
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60) || "engagement"
  );
}

function fmtTime(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

type ReportData = { md: string; at: string; model: string };

/**
 * The generated-report view for one engagement. Renders a persisted report if
 * the session already has one; otherwise auto-drafts on open (that's the intent
 * of the "Generate report" action). Regenerate / Download .md / Copy provided.
 */
export function ReportScreen({ id }: { id: string }) {
  const reduced = useReducedMotion();
  const fetched = useApi((s) => getSession(id, s), [id]);

  const [report, setReport] = useState<ReportData | null>(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const startedRef = useRef(false);

  const generate = useCallback(() => {
    setGenerating(true);
    setError(null);
    generateReport(id)
      .then((r) =>
        setReport({
          md: r.report_md,
          at: r.report_generated_at,
          model: r.model_used,
        })
      )
      .catch((err: unknown) =>
        setError(
          err instanceof ApiError ? err.message : "Couldn’t draft the report."
        )
      )
      .finally(() => setGenerating(false));
  }, [id]);

  // Seed from the persisted report, or auto-draft once if there isn't one yet.
  useEffect(() => {
    if (!fetched.data || startedRef.current) return;
    startedRef.current = true;
    if (fetched.data.report_md) {
      getLLMConfig()
        .then((cfg) =>
          setReport({
            md: fetched.data!.report_md!,
            at: fetched.data!.report_generated_at ?? "",
            model: cfg.model,
          })
        )
        .catch(() =>
          setReport({
            md: fetched.data!.report_md!,
            at: fetched.data!.report_generated_at ?? "",
            model: "the configured model",
          })
        );
    } else {
      generate();
    }
  }, [fetched.data, generate]);

  const download = useCallback(() => {
    if (!report) return;
    const label = fetched.data?.label ?? "engagement";
    const blob = new Blob([report.md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${slugify(label)}-report.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }, [report, fetched.data]);

  const label = fetched.data?.label ?? "engagement";

  // ---- loading / error shells ---- //
  if (fetched.loading) {
    return (
      <PageShell crumbs={[{ label: "home", href: "/" }, { label: "…" }]}>
        <div className="hp-rep">
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
        <div className="hp-rep">
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
  const thin = session.checked === 0;

  return (
    <PageShell
      crumbs={[
        { label: "home", href: "/" },
        { label: "engagements", href: "/engagements" },
        { label: session.label, href: `/engagement/${id}` },
        { label: "report" },
      ]}
    >
      <div className="hp-rep">
        <header className="hp-rep-head">
          <div>
            <div className="hp-rep-kicker">pentest report</div>
            <h1 className="hp-rep-title">{label}</h1>
          </div>
          <Link href={`/engagement/${id}`} className="hp-rep-back">
            ← back to engagement
          </Link>
        </header>

        {thin && !report && !generating && (
          <div className="hp-rep-thin">
            No steps are checked off yet. You can still generate a report, but
            capturing evidence — check steps and paste real output — makes a
            much stronger one.
          </div>
        )}

        {generating && <DraftingLoader model={session.path.model_used} />}

        {error && !generating && (
          <div className="hp-ap-error">
            <p className="hp-note-err">{error}</p>
            <p className="hp-ap-error-hint">
              The default provider is local Ollama — make sure it&apos;s running,
              or{" "}
              <button
                type="button"
                className="hp-ap-linklike"
                onClick={generate}
              >
                try again
              </button>
              .
            </p>
          </div>
        )}

        {report && !generating && (
          <motion.section
            initial={{ opacity: 0, y: reduced ? 0 : 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: reduced ? 0 : 0.4 }}
          >
            <div className="hp-rep-bar">
              <span className="hp-rep-byline">
                generated by <b>{report.model}</b>
                {report.at && (
                  <span className="hp-ap-local"> · {fmtTime(report.at)}</span>
                )}
              </span>
              <div className="hp-rep-actions">
                <button
                  type="button"
                  className="hp-rep-btn"
                  onClick={generate}
                  disabled={generating}
                >
                  ↻ regenerate
                </button>
                <button type="button" className="hp-rep-btn" onClick={download}>
                  ↓ download .md
                </button>
                <CopyButton text={report.md} />
              </div>
            </div>

            <article className="hp-rep-doc">
              <Markdown source={report.md} />
            </article>
          </motion.section>
        )}
      </div>
    </PageShell>
  );
}

/** On-theme "drafting your report…" state (reuses the compose-loader styling). */
function DraftingLoader({ model }: { model?: string }) {
  const reduced = useReducedMotion();
  const [i, setI] = useState(0);

  useEffect(() => {
    if (reduced) return;
    const t = setInterval(
      () => setI((n) => (n + 1) % DRAFT_STAGES.length),
      2000
    );
    return () => clearInterval(t);
  }, [reduced]);

  return (
    <div className="hp-ap-loading" role="status" aria-live="polite">
      <div className="hp-ap-scan" aria-hidden>
        <span className="hp-ap-scanline" />
      </div>
      <div className="hp-ap-loading-title">drafting your report…</div>
      <div className="hp-ap-loading-stage" aria-hidden>
        {reduced ? DRAFT_STAGES[0] : DRAFT_STAGES[i]}
      </div>
      <div className="hp-ap-loading-dots" aria-hidden>
        {DRAFT_STAGES.map((_, n) => (
          <span
            key={n}
            className={`hp-ap-loading-dot${n <= i ? " is-on" : ""}`}
          />
        ))}
      </div>
      <div className="hp-ap-loading-note">
        {model ? (
          <>
            writing with <b>{model}</b> — a full report takes longer than a path;
            this can be a couple of minutes locally.
          </>
        ) : (
          <>a full report can take a couple of minutes on a local model.</>
        )}
      </div>
    </div>
  );
}
