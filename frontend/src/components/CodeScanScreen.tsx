"use client";

import Link from "next/link";
import { useMemo, useState, type CSSProperties } from "react";
import { PageShell } from "./PageShell";
import {
  ApiError,
  getCodeScanTools,
  renderCodeScanReport,
  runCodeScan,
  type CodeScanFinding,
  type CodeScanResult,
  type CodeScanSeverity,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";

const SCAN_COLOR = "#7ec8a0";

const SEVERITIES: CodeScanSeverity[] = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR: Record<CodeScanSeverity, string> = {
  critical: "#ff5c7a",
  high: "#f0776a",
  medium: "#f0a24a",
  low: "#7ec8a0",
  info: "#8aa4c8",
};

/**
 * :code scan — STATIC application-security analysis.
 *
 * Point it at a codebase folder; the backend runs Semgrep (+ Bandit for Python) and
 * returns normalized findings. This is the DEFENSIVE side of HackPit: it READS code
 * to find bugs. Nothing is executed, no target is involved, and none of the
 * engagement / executor / target-lock machinery is in play here.
 */
export function CodeScanScreen() {
  const tools = useApi(getCodeScanTools, []);
  const [path, setPath] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<CodeScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<CodeScanSeverity | "all">("all");
  const [catFilter, setCatFilter] = useState<string>("all");
  const [exporting, setExporting] = useState(false);

  const missing = (tools.data?.tools ?? []).filter((t) => !t.installed);
  const semgrepMissing = !tools.data?.ready && !tools.loading && !!tools.data;

  async function scan() {
    const target = path.trim();
    if (!target || scanning) return;
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const data = await runCodeScan({ path: target });
      setResult(data);
      setSevFilter("all");
      setCatFilter("all");
    } catch (e) {
      const err = e as ApiError;
      setError(
        err?.message ??
          "The scan could not be completed. Check the path and that the backend is running."
      );
    } finally {
      setScanning(false);
    }
  }

  /**
   * Export the scan currently on screen. The backend renders the report from this exact
   * result rather than re-scanning, so the document can't drift from what was shown.
   */
  async function exportReport() {
    if (!result || exporting) return;
    setExporting(true);
    try {
      const doc = await renderCodeScanReport(result);
      const url = URL.createObjectURL(
        new Blob([doc.markdown], { type: "text/markdown;charset=utf-8" })
      );
      const a = document.createElement("a");
      a.href = url;
      a.download = doc.filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError((e as ApiError)?.message ?? "Could not render the report.");
    } finally {
      setExporting(false);
    }
  }

  const shown = useMemo<CodeScanFinding[]>(() => {
    const all = result?.findings ?? [];
    return all.filter(
      (f) =>
        (sevFilter === "all" || f.severity === sevFilter) &&
        (catFilter === "all" || f.category === catFilter)
    );
  }, [result, sevFilter, catFilter]);

  const categories = useMemo(
    () => Object.keys(result?.summary.by_category ?? {}),
    [result]
  );

  return (
    <PageShell crumbs={[{ label: "home", href: "/" }, { label: "Code scan" }]}>
      <div className="hp-cs">
        <header className="hp-listing-head">
          <span className="hp-listing-ic" style={{ ["--cc" as string]: SCAN_COLOR }}>
            {"◈"}
          </span>
          <div>
            <h1 className="hp-listing-title">Code scan</h1>
            <p className="hp-listing-sub">
              Static application-security analysis — Semgrep + Bandit read a codebase
              and report what they find.
            </p>
          </div>
        </header>

        {/* The framing, stated once and plainly. */}
        <p className="hp-cs-note">
          <b>Static only.</b> The scanners parse your source files — nothing here runs
          the code being scanned, and no target, network or engagement is involved.
          Read-only on the codebase.
        </p>

        {semgrepMissing && (
          <div className="hp-cs-missing">
            <b>Scanners not installed.</b> Install them into the backend environment,
            then reload:
            <code>cd backend &amp;&amp; uv pip install semgrep bandit</code>
          </div>
        )}

        <div className="hp-cs-bar">
          <label className="hp-cs-field">
            <span>codebase folder</span>
            <input
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void scan();
              }}
              placeholder="e.g. C:\\Users\\you\\projects\\my-app  (a folder, not a file)"
              spellCheck={false}
              autoComplete="off"
              disabled={scanning}
            />
          </label>
          <button
            type="button"
            className="hp-cs-run"
            onClick={() => void scan()}
            disabled={scanning || !path.trim()}
          >
            {scanning ? "scanning…" : "Scan"}
          </button>
        </div>

        {missing.length > 0 && !semgrepMissing && (
          <p className="hp-cs-hint">
            {missing.map((t) => t.name).join(", ")} not installed — those checks are
            skipped. <code>{missing[0].install_hint}</code>
          </p>
        )}

        {scanning && (
          <div className="hp-cs-loading">
            Reading the tree and running the scanners — large codebases take a moment.
          </div>
        )}

        {error && <div className="hp-cs-error">⚠ {error}</div>}

        {result && !scanning && (
          <>
            <div className="hp-cs-summary">
              <div className="hp-cs-sumhead">
                <b>{result.summary.total}</b> findings in{" "}
                <b>{result.summary.files_affected}</b> files ·{" "}
                {result.files_scanned} files scanned · {result.duration_s}s ·{" "}
                {result.tools_run.join(" + ") || "no scanner"}
                <button
                  type="button"
                  className="hp-cs-export"
                  onClick={() => void exportReport()}
                  disabled={exporting}
                >
                  {exporting ? "rendering…" : "export report ↓"}
                </button>
              </div>
              <div className="hp-cs-sevbar">
                {SEVERITIES.map((s) => {
                  const n = result.summary.by_severity[s] ?? 0;
                  if (!n) return null;
                  return (
                    <button
                      key={s}
                      type="button"
                      className={`hp-cs-sevchip${sevFilter === s ? " hp-on" : ""}`}
                      style={{ ["--sc" as string]: SEV_COLOR[s] } as CSSProperties}
                      onClick={() => setSevFilter(sevFilter === s ? "all" : s)}
                    >
                      <b>{n}</b> {s}
                    </button>
                  );
                })}
                {(sevFilter !== "all" || catFilter !== "all") && (
                  <button
                    type="button"
                    className="hp-cs-clear"
                    onClick={() => {
                      setSevFilter("all");
                      setCatFilter("all");
                    }}
                  >
                    clear filters
                  </button>
                )}
              </div>
              {categories.length > 0 && (
                <div className="hp-cs-cats">
                  {categories.map((c) => (
                    <button
                      key={c}
                      type="button"
                      className={`hp-cs-cat${catFilter === c ? " hp-on" : ""}`}
                      onClick={() => setCatFilter(catFilter === c ? "all" : c)}
                    >
                      {c} <span>{result.summary.by_category[c]}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {result.warnings.length > 0 && (
              <ul className="hp-cs-warnings">
                {result.warnings.map((w) => (
                  <li key={w}>⚠ {w}</li>
                ))}
              </ul>
            )}

            {result.summary.total === 0 ? (
              <div className="hp-cs-empty">
                <b>No findings.</b> The scanners had nothing to report for this tree
                with the bundled ruleset. That is not a clean bill of health — it means
                these rules matched nothing.
              </div>
            ) : shown.length === 0 ? (
              <div className="hp-cs-empty">
                No findings match the current filters.
              </div>
            ) : (
              <ul className="hp-cs-list">
                {shown.map((f, i) => (
                  <li
                    key={`${f.file}:${f.line}:${f.rule_id}:${i}`}
                    className="hp-cs-row"
                    style={{ ["--sc" as string]: SEV_COLOR[f.severity] } as CSSProperties}
                  >
                    <div className="hp-cs-rowhead">
                      <span className="hp-cs-sev">{f.severity}</span>
                      <code className="hp-cs-loc">
                        {f.file}:{f.line}
                      </code>
                      <span className="hp-cs-rule">{f.rule_id}</span>
                      <span className="hp-cs-tool">
                        {f.tools.length > 1 ? `${f.tools.join(" + ")} agree` : f.tool}
                      </span>
                    </div>
                    <p className="hp-cs-msg">{f.message}</p>
                    <div className="hp-cs-meta">
                      <span className="hp-cs-tag">{f.category}</span>
                      {f.cwe && <span className="hp-cs-tag">{f.cwe}</span>}
                      {f.owasp && <span className="hp-cs-tag">{f.owasp}</span>}
                      {f.confidence && (
                        <span className="hp-cs-tag">confidence: {f.confidence.toLowerCase()}</span>
                      )}
                      {f.kb_entry_id && (
                        <Link
                          href={`/entry/${encodeURIComponent(f.kb_entry_id)}`}
                          className="hp-cs-kb"
                        >
                          technique: {f.kb_title} →
                        </Link>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>
    </PageShell>
  );
}
