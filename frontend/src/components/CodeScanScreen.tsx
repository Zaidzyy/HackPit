"use client";

import Link from "next/link";
import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { PageShell } from "./PageShell";
import {
  ApiError,
  getCodeAuditSample,
  getCodePlaybooks,
  getCodeScanTools,
  proposeToolPass,
  renderCodeScanReport,
  runCodeAudit,
  runCodeScan,
  type AuditFinding,
  type AuditPlaybook,
  type AuditResult,
  type AuditSeverity,
  type CodeScanFinding,
  type CodeScanResult,
  type CodeScanSeverity,
  type ToolProposal,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";

const SCAN_COLOR = "#7ec8a0";

const SEVERITIES: CodeScanSeverity[] = ["critical", "high", "medium", "low", "info"];
/** The severities worth opening on. A repo-wide scan returns hundreds of `low` findings —
 *  mostly Bandit `assert_used` in test files — and opening on all of them buries the few
 *  that matter. Low/info are one click away, never removed. */
const IMPORTANT: CodeScanSeverity[] = ["critical", "high", "medium"];
type SevFilter = CodeScanSeverity | "all" | "important";
const SEV_COLOR: Record<CodeScanSeverity, string> = {
  critical: "#ff5c7a",
  high: "#f0776a",
  medium: "#f0a24a",
  low: "#7ec8a0",
  info: "#8aa4c8",
};
const AUDIT_SEV_COLOR: Record<AuditSeverity, string> = {
  critical: "#ff5c7a",
  high: "#f0776a",
  medium: "#f0a24a",
  low: "#7ec8a0",
  informational: "#8aa4c8",
};
const AUDIT_SEVERITIES: AuditSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

type Tab = "rules" | "ai";

/**
 * :code scan — STATIC application-security analysis.
 *
 * Two modes over the same read-only footprint:
 *  - RULES: Semgrep (+ Bandit) pattern-match the tree file-by-file.
 *  - AI AUDIT: an agent fan-out that maps the entrypoints/flows ONCE, hands each downstream
 *    agent exactly one flow to verify against source, and returns concrete
 *    vuln-with-attacker-path findings (or honest stubs), deduped + severity-ranked.
 *
 * Neither mode executes the scanned code, takes a target, or touches the engagement / executor /
 * target-lock machinery. Any PoC an AI finding suggests is a STRING to run approve-each through
 * the existing gated executor — never from here.
 */
export function CodeScanScreen() {
  const [tab, setTab] = useState<Tab>("rules");

  // ---- AI-audit state ---------------------------------------------------- //
  const [aiResult, setAiResult] = useState<AuditResult | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [auditPath, setAuditPath] = useState("");
  const [patchedSince, setPatchedSince] = useState("");
  const [openPoc, setOpenPoc] = useState<Set<number>>(new Set());
  const [playbook, setPlaybook] = useState<string>("external-flow-analysis");
  const [playbooks, setPlaybooks] = useState<AuditPlaybook[]>([]);
  const [toolProposals, setToolProposals] = useState<ToolProposal[] | null>(null);
  const [toolLoading, setToolLoading] = useState(false);

  // The built-in playbooks the picker offers (web app + the three web3 ones).
  useEffect(() => {
    getCodePlaybooks()
      .then((d) => setPlaybooks(d.playbooks))
      .catch(() => setPlaybooks([]));
  }, []);

  // On a ?demo=<web3|ai|playbook-key> deep link, load the matching bundled sample so the screen
  // renders without input (used by the headless screenshot). Deferred to a microtask so no
  // setState runs synchronously in the effect body — keeps the accepted lint baseline unchanged.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const demo = new URLSearchParams(window.location.search).get("demo");
    if (!demo) return;
    const pb =
      demo === "ai" || demo === "1"
        ? "external-flow-analysis"
        : demo === "web3"
          ? "evm-external-flow"
          : demo; // a playbook key passes through
    void Promise.resolve().then(() => void loadSample(pb));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runAudit() {
    const target = auditPath.trim();
    if (!target || aiLoading) return;
    setAiLoading(true);
    setAiError(null);
    setAiResult(null);
    setToolProposals(null);
    try {
      const data = await runCodeAudit({
        path: target,
        patched_since: patchedSince.trim() || null,
        playbook,
        mode: "auto",
      });
      setTab("ai");
      setAiResult(data);
      setOpenPoc(new Set());
    } catch (e) {
      setAiError(
        (e as ApiError)?.message ??
          "The audit could not be run. Check the path and that the backend is running."
      );
    } finally {
      setAiLoading(false);
    }
  }

  async function loadSample(pbKey?: string) {
    if (aiLoading) return;
    const pb = pbKey ?? playbook;
    setAiLoading(true);
    setAiError(null);
    setToolProposals(null);
    if (pbKey) setPlaybook(pbKey);
    try {
      const data = await getCodeAuditSample(pb);
      setTab("ai");
      setAiResult(data);
      setOpenPoc(new Set());
    } catch (e) {
      setAiError((e as ApiError)?.message ?? "Could not load the sample audit.");
    } finally {
      setAiLoading(false);
    }
  }

  // Propose (never run) a slither/mythril/echidna tool pass over the audited contract path.
  async function loadToolPass() {
    if (!aiResult || toolLoading) return;
    setToolLoading(true);
    try {
      const d = await proposeToolPass({
        path: aiResult.repo,
        chain: aiResult.chain || undefined,
        playbook: aiResult.playbook,
      });
      setToolProposals(d.proposals);
    } catch {
      setToolProposals([]);
    } finally {
      setToolLoading(false);
    }
  }

  function togglePoc(i: number) {
    setOpenPoc((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  }

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
              Static application-security analysis — a rule scan, or an AI-agent audit that
              fans out one agent per flow.
            </p>
          </div>
        </header>

        <div className="hp-cs-mode" role="tablist" aria-label="scan mode">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "rules"}
            className={`hp-cs-modebtn${tab === "rules" ? " hp-on" : ""}`}
            onClick={() => setTab("rules")}
          >
            Rules scan
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "ai"}
            className={`hp-cs-modebtn${tab === "ai" ? " hp-on" : ""}`}
            onClick={() => setTab("ai")}
          >
            AI audit
          </button>
        </div>

        {tab === "rules" ? (
          <RulesScan />
        ) : (
          <AiAudit
            result={aiResult}
            loading={aiLoading}
            error={aiError}
            path={auditPath}
            setPath={setAuditPath}
            patchedSince={patchedSince}
            setPatchedSince={setPatchedSince}
            playbook={playbook}
            setPlaybook={setPlaybook}
            playbooks={playbooks}
            onRun={() => void runAudit()}
            onSample={() => void loadSample()}
            openPoc={openPoc}
            togglePoc={togglePoc}
            toolProposals={toolProposals}
            toolLoading={toolLoading}
            onToolPass={() => void loadToolPass()}
          />
        )}
      </div>
    </PageShell>
  );
}

// --------------------------------------------------------------------------- //
// AI audit
// --------------------------------------------------------------------------- //
function AiAudit(props: {
  result: AuditResult | null;
  loading: boolean;
  error: string | null;
  path: string;
  setPath: (v: string) => void;
  patchedSince: string;
  setPatchedSince: (v: string) => void;
  playbook: string;
  setPlaybook: (v: string) => void;
  playbooks: AuditPlaybook[];
  onRun: () => void;
  onSample: () => void;
  openPoc: Set<number>;
  togglePoc: (i: number) => void;
  toolProposals: ToolProposal[] | null;
  toolLoading: boolean;
  onToolPass: () => void;
}) {
  const {
    result,
    loading,
    error,
    path,
    setPath,
    patchedSince,
    setPatchedSince,
    playbook,
    setPlaybook,
    playbooks,
    onRun,
    onSample,
    openPoc,
    togglePoc,
    toolProposals,
    toolLoading,
    onToolPass,
  } = props;

  const activePb = playbooks.find((p) => p.key === playbook);
  const isWeb3 = !!activePb?.chain;

  return (
    <>
      <p className="hp-cs-note">
        <b>Agent fan-out, read-only.</b> The audit maps the repo&apos;s externally-reachable
        entrypoints and their flows <b>once</b>, then hands each downstream agent exactly{" "}
        <b>one</b> flow to verify against source — returning a concrete vuln-with-attacker-path
        or an honest no-finding stub. Findings are deduped and severity-ranked. Nothing here
        executes the code, and any PoC is a proposal to run <b>approve-each</b> through the
        executor.
      </p>

      <div className="hp-cs-bar">
        {playbooks.length > 0 && (
          <label className="hp-cs-field">
            <span>playbook</span>
            <select
              value={playbook}
              onChange={(e) => setPlaybook(e.target.value)}
              disabled={loading}
              title={activePb?.description}
            >
              {playbooks.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="hp-cs-field">
          <span>{isWeb3 ? "contract folder" : "repo folder"}</span>
          <input
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onRun();
            }}
            placeholder={
              isWeb3
                ? "e.g. C:\\Users\\you\\audits\\vault  (the contracts folder)"
                : "e.g. C:\\Users\\you\\projects\\my-service  (a folder, not a file)"
            }
            spellCheck={false}
            autoComplete="off"
            disabled={loading}
          />
        </label>
        <label className="hp-cs-field hp-cs-field-narrow">
          <span>patched-since (git ref)</span>
          <input
            type="text"
            value={patchedSince}
            onChange={(e) => setPatchedSince(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onRun();
            }}
            placeholder="optional — e.g. main, v1.2.0, HEAD~20"
            spellCheck={false}
            autoComplete="off"
            disabled={loading}
          />
        </label>
        <button
          type="button"
          className="hp-cs-run"
          onClick={onRun}
          disabled={loading || !path.trim()}
        >
          {loading ? "auditing…" : "Run AI audit"}
        </button>
        <button
          type="button"
          className="hp-cs-sample"
          onClick={onSample}
          disabled={loading}
          title="Audit the bundled synthetic sample repo (deterministic, no LLM)"
        >
          sample repo
        </button>
      </div>

      <p className="hp-cs-hint">
        <b>One approved job.</b> A single run fans out into many analysis tasks — the ZAP /
        nuclei justification — and adds no new gate. With <code>patched-since</code> set, only
        the files changed since that git ref are audited.
      </p>

      {loading && (
        <div className="hp-cs-loading">
          Mapping entrypoints, tracing flows, and fanning out one agent per flow…
        </div>
      )}
      {error && <div className="hp-cs-error">⚠ {error}</div>}

      {result && !loading && (
        <AuditReport
          result={result}
          openPoc={openPoc}
          togglePoc={togglePoc}
          toolProposals={toolProposals}
          toolLoading={toolLoading}
          onToolPass={onToolPass}
        />
      )}
    </>
  );
}

function AuditReport({
  result,
  openPoc,
  togglePoc,
  toolProposals,
  toolLoading,
  onToolPass,
}: {
  result: AuditResult;
  openPoc: Set<number>;
  togglePoc: (i: number) => void;
  toolProposals: ToolProposal[] | null;
  toolLoading: boolean;
  onToolPass: () => void;
}) {
  const s = result.summary;
  return (
    <>
      <div className="hp-cs-summary">
        <div className="hp-cs-sumhead">
          <b>{s.findings}</b> ranked finding{s.findings === 1 ? "" : "s"} ·{" "}
          <b>{s.entrypoints}</b> entrypoints mapped · <b>{s.flows}</b> flows fanned out ·{" "}
          <b>{s.stubs}</b> no-finding stub{s.stubs === 1 ? "" : "s"} · {result.duration_s}s
        </div>
        <div className="hp-cs-badges">
          <span className="hp-cs-badge">{result.mode === "ai" ? "LLM agents" : "heuristic analyst"}</span>
          <span className="hp-cs-badge">{result.playbook}</span>
          {result.chain && (
            <span className="hp-cs-badge hp-cs-badge-chain">{result.chain}</span>
          )}
          {result.is_sample && <span className="hp-cs-badge">sample repo</span>}
          {result.grounded && <span className="hp-cs-badge">KB-grounded</span>}
          {result.changed_only && (
            <span className="hp-cs-badge">patched-since {result.patched_since}</span>
          )}
          {typeof result.persisted === "number" && result.persisted > 0 && (
            <span className="hp-cs-badge hp-cs-badge-ok">
              {result.persisted} → engagement state
            </span>
          )}
        </div>
        {s.findings > 0 && (
          <div className="hp-cs-sevbar">
            {AUDIT_SEVERITIES.map((sev) => {
              const n = s.by_severity[sev] ?? 0;
              if (!n) return null;
              return (
                <span
                  key={sev}
                  className="hp-cs-sevchip"
                  style={{ ["--sc" as string]: AUDIT_SEV_COLOR[sev] } as CSSProperties}
                >
                  <b>{n}</b> {sev}
                </span>
              );
            })}
          </div>
        )}
      </div>

      {/* web3: a slither/mythril/echidna tool pass — PROPOSE-ONLY, run approve-each */}
      {result.chain && (
        <div className="hp-cs-toolpass">
          <div className="hp-cs-toolpass-head">
            <div>
              <b>Tool pass</b> — corroborate with slither / mythril / echidna. Propose-only:
              nothing here runs a scanner. Each command is confirmed <b>approve-each</b> in the
              :kali sandbox.
            </div>
            <button
              type="button"
              className="hp-cs-run"
              onClick={onToolPass}
              disabled={toolLoading}
            >
              {toolLoading ? "proposing…" : toolProposals ? "refresh tool pass" : "Propose tool pass"}
            </button>
          </div>
          {toolProposals && toolProposals.length === 0 && (
            <p className="hp-cs-hint">No tool pass is defined for this chain.</p>
          )}
          {toolProposals && toolProposals.length > 0 && (
            <ul className="hp-cs-toollist">
              {toolProposals.map((t) => (
                <li key={t.tool} className="hp-cs-toolrow">
                  <div className="hp-cs-toolmeta">
                    <span className="hp-cs-tool">{t.tool}</span>
                    <span className="hp-cs-toolkind">{t.kind}</span>
                    {t.parseable && <span className="hp-cs-tag">parses back into findings</span>}
                  </div>
                  <code className="hp-cs-poc-cmd">{t.command}</code>
                  <p className="hp-cs-poc-note">{t.purpose}</p>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {result.warnings.length > 0 && (
        <ul className="hp-cs-warnings">
          {result.warnings.map((w) => (
            <li key={w}>⚠ {w}</li>
          ))}
        </ul>
      )}

      {/* the map, made once */}
      <div className="hp-cs-map">
        <div className="hp-cs-maphead">
          Attack surface mapped once → <b>{result.flows.length}</b> flows fanned out, one agent
          each
        </div>
        <div className="hp-cs-eps">
          {result.entrypoints.map((ep) => {
            const flows = result.flows.filter((f) => f.entrypoint_id === ep.id).length;
            return (
              <div key={ep.id} className="hp-cs-ep">
                <span className="hp-cs-ep-kind">{ep.kind}</span>
                <span className="hp-cs-ep-name">{ep.name}</span>
                <span className="hp-cs-ep-file">{ep.file}</span>
                <span className="hp-cs-ep-flows">{flows} flow{flows === 1 ? "" : "s"}</span>
              </div>
            );
          })}
          {result.entrypoints.length === 0 && (
            <div className="hp-cs-empty">No externally-reachable entrypoints were mapped.</div>
          )}
        </div>
      </div>

      {/* the ranked findings */}
      {s.findings === 0 ? (
        <div className="hp-cs-empty">
          <b>No concrete findings.</b> Every flow the agents verified came back a stub. That is
          not a clean bill of health — it means no attacker path was proven on the mapped flows.
        </div>
      ) : (
        <ul className="hp-cs-list">
          {result.findings.map((f, i) => (
            <AuditFindingRow
              key={`${f.title}:${i}`}
              f={f}
              open={openPoc.has(i)}
              onToggle={() => togglePoc(i)}
            />
          ))}
        </ul>
      )}
    </>
  );
}

function AuditFindingRow({
  f,
  open,
  onToggle,
}: {
  f: AuditFinding;
  open: boolean;
  onToggle: () => void;
}) {
  const color = AUDIT_SEV_COLOR[f.severity] ?? "#8aa4c8";
  return (
    <li className="hp-cs-row" style={{ ["--sc" as string]: color } as CSSProperties}>
      <div className="hp-cs-rowhead">
        <span className="hp-cs-sev">{f.severity}</span>
        <span className="hp-cs-ai-title">{f.title}</span>
        {f.confidence && <span className="hp-cs-tool">{f.confidence} confidence</span>}
      </div>

      <div className="hp-cs-ai-path">
        <span className="hp-cs-ai-pathlabel">attacker path</span>
        <p>{f.attacker_path}</p>
      </div>

      {f.impact && (
        <p className="hp-cs-ai-impact">
          <b>Impact:</b> {f.impact}
        </p>
      )}

      <div className="hp-cs-meta">
        {f.chain && <span className="hp-cs-tag hp-cs-badge-chain">{f.chain}</span>}
        {(f.contract || f.function) && (
          <span className="hp-cs-tag">
            {f.contract}
            {f.contract && f.function ? "::" : ""}
            {f.function}
          </span>
        )}
        {f.vuln_class && <span className="hp-cs-tag">{f.vuln_class}</span>}
        {f.cwe && <span className="hp-cs-tag">{f.cwe}</span>}
        {f.source_refs.map((r) => (
          <span key={r} className="hp-cs-loc">
            {r}
          </span>
        ))}
        {f.kb_refs.map((k) => (
          <Link key={k.id} href={`/entry/${encodeURIComponent(k.id)}`} className="hp-cs-kb">
            {k.title || k.id} →
          </Link>
        ))}
      </div>

      {f.poc && (
        <div className="hp-cs-pocwrap">
          <button type="button" className="hp-cs-poc" onClick={onToggle}>
            {open ? "hide PoC" : "Build PoC (approve-each)"}
          </button>
          {open && (
            <div className="hp-cs-poc-box">
              <code className="hp-cs-poc-cmd">{f.poc}</code>
              <p className="hp-cs-poc-note">
                Propose-only. Nothing here runs it — take this to the executor and confirm it
                <b> approve-each</b> in the :kali sandbox.
              </p>
            </div>
          )}
        </div>
      )}
    </li>
  );
}

// --------------------------------------------------------------------------- //
// Rules scan (the original Semgrep/Bandit pattern scan — unchanged behaviour)
// --------------------------------------------------------------------------- //
function RulesScan() {
  const tools = useApi(getCodeScanTools, []);
  const [path, setPath] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<CodeScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<SevFilter>("important");
  const [catFilter, setCatFilter] = useState<string>("all");
  const [exporting, setExporting] = useState(false);
  const [ruleset, setRuleset] = useState("bundled");

  const missing = (tools.data?.tools ?? []).filter((t) => !t.installed);
  const semgrepMissing = !tools.data?.ready && !tools.loading && !!tools.data;

  async function scan() {
    const target = path.trim();
    if (!target || scanning) return;
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const data = await runCodeScan({ path: target, semgrep_config: ruleset });
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
        (sevFilter === "all" ||
          (sevFilter === "important"
            ? IMPORTANT.includes(f.severity)
            : f.severity === sevFilter)) &&
        (catFilter === "all" || f.category === catFilter)
    );
  }, [result, sevFilter, catFilter]);

  const categories = useMemo(
    () => Object.keys(result?.summary.by_category ?? {}),
    [result]
  );

  return (
    <>
      <p className="hp-cs-note">
        <b>Static only.</b> The scanners parse your source files — nothing here runs the code
        being scanned, and no target, network or engagement is involved. Read-only on the
        codebase.
      </p>

      {semgrepMissing && (
        <div className="hp-cs-missing">
          <b>Scanners not installed.</b> Install them into the backend environment, then reload:
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
        {(tools.data?.rulesets?.length ?? 0) > 0 && (
          <label className="hp-cs-field">
            <span>ruleset</span>
            <select
              value={ruleset}
              onChange={(e) => setRuleset(e.target.value)}
              disabled={scanning}
            >
              {tools.data!.rulesets!.map((r) => (
                <option key={r.key} value={r.key}>
                  {r.label}
                </option>
              ))}
            </select>
          </label>
        )}
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
          {missing.map((t) => t.name).join(", ")} not installed — those checks are skipped.{" "}
          <code>{missing[0].install_hint}</code>
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
              <b>{result.summary.files_affected}</b> files · {result.files_scanned} files
              scanned · {result.duration_s}s · {result.tools_run.join(" + ") || "no scanner"}
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
              <button
                type="button"
                className={`hp-cs-scope${sevFilter === "important" ? " hp-on" : ""}`}
                onClick={() => setSevFilter("important")}
                title="Show critical, high and medium only"
              >
                medium+
              </button>
              <button
                type="button"
                className={`hp-cs-scope${sevFilter === "all" ? " hp-on" : ""}`}
                onClick={() => setSevFilter("all")}
                title="Show every finding, including low and info"
              >
                all {result.summary.total}
              </button>
              <span className="hp-cs-sevsep" aria-hidden />
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
              {(sevFilter !== "important" || catFilter !== "all") && (
                <button
                  type="button"
                  className="hp-cs-clear"
                  onClick={() => {
                    setSevFilter("important");
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
              <b>No findings.</b> The scanners had nothing to report for this tree with the
              bundled ruleset. That is not a clean bill of health — it means these rules matched
              nothing.
            </div>
          ) : shown.length === 0 ? (
            <div className="hp-cs-empty">No findings match the current filters.</div>
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
    </>
  );
}
