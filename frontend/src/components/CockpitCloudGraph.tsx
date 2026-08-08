"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { CockpitCloudOrchestrator } from "./CockpitCloudOrchestrator";
import { CockpitCloudSeed } from "./CockpitCloudSeed";
import { DetectionDisclosure } from "./DetectionPanel";
import {
  ApiError,
  cloudComputePath,
  cloudGetGraph,
  cloudIngest,
  cloudSeedImds,
  execCockpitStream,
  type CloudNode,
  type CloudPathEdge,
  type CloudPathResult,
  type CloudProvider,
  type CloudSeedResult,
  type CloudTechnique,
  type ExecEvent,
} from "@/lib/api";

/**
 * The cloud IAM privilege-escalation graph — the route from an owned/captured principal to an
 * admin/owner-equivalent principal, rendered in the cockpit's kill-chain cinematic style: typed
 * nodes ignite in sequence along the route, each edge is labeled with its IAM abuse, and clicking
 * an edge opens a drawer with the KB-grounded technique + the concrete CLI command.
 *
 * WALK THE PATH: from the drawer the human can send an edge's abuse command to the SAME gated
 * executor every cockpit command uses (approve-each; engagement scope-locked; heuristic
 * red-confirm). It NEVER auto-runs. The agent may PROPOSE the next edge (an index into the real
 * frontier), but the human still approves each. This component only proposes + streams the gated
 * executor; it has no other way to run anything.
 */

const IGNITE_STEP = 0.14;
const IGNITE_DUR = 0.44;

type Line = { kind: "stdout" | "stderr" | "meta" | "err"; text: string };

const NODE_ICON: Record<CloudNode["type"], string> = {
  user: "👤",
  role: "🎭",
  group: "👥",
  serviceaccount: "🤖",
  bucket: "🪣",
  function: "⚡",
  secret: "🔑",
  kmskey: "🗝️",
  policy: "📜",
  account: "☁️",
  resource: "📦",
};

const PROVIDERS: { id: CloudProvider; label: string }[] = [
  { id: "aws", label: "AWS" },
  { id: "azure", label: "Azure" },
  { id: "gcp", label: "GCP" },
];

// The synthetic sample's owned start principal — matches cloudgraph/sample_data.py (dev-alice).
const SAMPLE_START = "arn:aws:iam::123456789012:user/dev-alice";

/** A readable name from an ARN / resource id — the last path or `:` segment. */
function shortLabel(label: string): string {
  const tail = label.split(":").pop() ?? label;
  return tail.split("/").pop() || label;
}

export function CockpitCloudGraph({
  sessionId = null,
  engagementId = null,
  scopeLabel = null,
}: {
  sessionId?: string | null;
  /** When set, walking a step runs in REAL-TARGET engagement mode against this engagement. */
  engagementId?: string | null;
  scopeLabel?: string | null;
}) {
  const [provider, setProvider] = useState<CloudProvider>("aws");
  const [graphId, setGraphId] = useState<string | null>(null);
  const [account, setAccount] = useState<string | null>(null);
  const [graphProvider, setGraphProvider] = useState<string | null>(null);
  // ORCHESTRATION STATE — which principals the operator controls and which edges are walked.
  const [owned, setOwned] = useState<string[]>([]);
  const [traversed, setTraversed] = useState<string[]>([]);
  const [nodes, setNodes] = useState<Map<string, CloudNode>>(new Map());
  const [result, setResult] = useState<CloudPathResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);

  const [openEdge, setOpenEdge] = useState<number | null>(null);
  const [walked, setWalked] = useState<Set<number>>(new Set());

  // walk-the-path exec stream
  const [running, setRunning] = useState<number | null>(null);
  const [dangerAck, setDangerAck] = useState(false);
  const [lines, setLines] = useState<Line[]>([]);
  const [exitCode, setExitCode] = useState<number | null>(null);
  const ctrlRef = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);

  const autoloaded = useRef(false);
  const [autoSeed, setAutoSeed] = useState(false);

  useEffect(() => () => ctrlRef.current?.abort(), []);
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [lines]);

  const path = result?.found ? result.path : null;

  // Seeding + the sample share ONE session so a seeded identity merges into the enumerated graph.
  // When no session is supplied (the standalone /cockpit/cloud demo), a stable local id is used.
  const effectiveSession = sessionId ?? "cloud-demo";

  const ingestSample = useCallback(async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    setWalked(new Set());
    setOpenEdge(null);
    try {
      const ing = await cloudIngest({ use_sample: true, session_id: effectiveSession });
      setGraphId(ing.graph_id);
      setAccount(ing.account);
      setGraphProvider(ing.provider);
      setProvider((ing.provider as CloudProvider) || "aws");
      setOwned([SAMPLE_START]);
      setTraversed([]);
      setWarnings(ing.warnings);
      // compute the route to an admin principal (sample owned start is dev-alice) + node map
      const [pathRes, g] = await Promise.all([
        cloudComputePath({ graph_id: ing.graph_id, start: SAMPLE_START, with_techniques: true }),
        cloudGetGraph(ing.graph_id),
      ]);
      const nm = new Map<string, CloudNode>();
      for (const n of g.nodes) nm.set(n.id, n);
      const s = nm.get(SAMPLE_START);
      if (s) nm.set(SAMPLE_START, { ...s, owned: true });
      setNodes(nm);
      setResult(pathRes);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Couldn’t load the cloud graph.");
    } finally {
      setLoading(false);
    }
  }, [effectiveSession]);

  // SSRF→IMDS seed: parse a captured IMDS body into an OWNED principal, seed it into this session's
  // graph, then refresh the graph and route FROM the seeded identity toward an admin principal. The
  // POST runs nothing — the IMDS fetch already went through the human-approved executor. Returns the
  // seed result so the panel can show the parsed identity / expiry / warnings.
  const handleSeed = useCallback(
    async (
      prov: CloudProvider,
      responseBody: string,
      src: "repeater" | "oob" | "paste",
      roleHint: string
    ): Promise<CloudSeedResult> => {
      const res = await cloudSeedImds({
        session_id: effectiveSession,
        provider: prov,
        response_body: responseBody,
        source: src,
        role_hint: roleHint || null,
        engagement_id: engagementId ?? undefined,
      });
      const g = await cloudGetGraph(res.graph_id);
      const nm = new Map<string, CloudNode>();
      for (const n of g.nodes) nm.set(n.id, n);
      setNodes(nm);
      setGraphId(res.graph_id);
      setAccount(g.account);
      setGraphProvider(g.provider);
      setProvider((g.provider as CloudProvider) || prov);
      setOwned([res.node_id]);
      setTraversed([]);
      setWarnings(g.warnings);
      setWalked(new Set());
      setOpenEdge(null);
      try {
        const pathRes = await cloudComputePath({
          graph_id: res.graph_id,
          start: res.node_id,
          with_techniques: true,
        });
        setResult(pathRes);
      } catch {
        // A freshly-seeded standalone identity may have no route yet — keep the graph, show why.
        setResult({
          found: false,
          path: null,
          alternatives: [],
          reason:
            "seeded identity has no route to an admin principal yet — enumerate as it (gated) to " +
            "expand the graph, or seed onto an enumerated node",
          target: "",
          target_label: "",
        });
      }
      return res;
    },
    [effectiveSession, engagementId]
  );

  // Deep-link auto-load, so the headless-Edge screenshot renders content, not the empty state.
  //   ?demo=1 → ingest the synthetic sample (route from dev-alice).
  //   ?seed=1 → ingest the sample AND seed a synthetic SSRF/IMDS identity (ci-deployer), so the
  //             screenshot shows the seed panel with a parsed result + the owned node routing.
  // The setState all lives inside the async bodies (not this effect), so it stays at the lint
  // baseline (frontend/AGENTS.md).
  useEffect(() => {
    if (autoloaded.current) return;
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    if (params.has("seed")) {
      autoloaded.current = true;
      // Ingest the sample first (so the seed merges onto the enumerated ci-deployer node), then let
      // the seed panel auto-seed the synthetic identity — its result renders in the panel.
      // setState lives in ingestSample()'s async body, but Next 16's set-state-in-effect flags
      // calling a setState-carrying callback from an effect regardless. Deliberate — keep the
      // counted lint baseline at 11 (frontend/AGENTS.md).
      // eslint-disable-next-line react-hooks/set-state-in-effect
      void ingestSample().then(() => setAutoSeed(true));
    } else if (params.has("demo")) {
      autoloaded.current = true;
      void ingestSample();
    }
  }, [ingestSample]);

  const nodeOf = useCallback(
    (id: string): CloudNode =>
      nodes.get(id) ?? {
        id,
        type: "resource",
        label: id,
        provider: "",
        high_value: false,
        owned: false,
        props: {},
      },
    [nodes]
  );

  const walk = useCallback(
    (idx: number, tech: CloudTechnique) => {
      if (!path || running !== null) return;
      const cmd = tech.commands[0]?.cmd ?? "";
      const parts = tokenize(cmd);
      if (parts.length === 0) return;
      ctrlRef.current?.abort();
      const ctrl = new AbortController();
      ctrlRef.current = ctrl;
      setRunning(idx);
      setExitCode(null);
      setLines([{ kind: "meta", text: `$ ${cmd.split("\n")[0]}` }]);
      const push = (l: Line) => setLines((prev) => [...prev, l]);

      execCockpitStream(
        {
          command: parts[0],
          args: parts.slice(1),
          approved: true, // set ONLY here, after the human clicked "approve & run" on this edge
          dangerous_ack: dangerAck,
          engagement_id: engagementId ?? undefined,
          session_id: sessionId ?? undefined,
        },
        (ev: ExecEvent) => {
          switch (ev.type) {
            case "start":
              push({ kind: "meta", text: `▶ run ${ev.run_id} → ${ev.target} [${ev.mode ?? "?"}]` });
              break;
            case "stdout":
              push({ kind: "stdout", text: ev.line });
              break;
            case "stderr":
              push({ kind: "stderr", text: ev.line });
              break;
            case "rejected":
              push({ kind: "err", text: `✕ rejected [${ev.gate}] — ${ev.reason}` });
              break;
            case "error":
              push({ kind: "err", text: `✕ ${ev.reason}` });
              break;
            case "exit":
              setExitCode(ev.code);
              push({ kind: "meta", text: `■ exit ${ev.code}` });
              setWalked((w) => new Set(w).add(idx));
              break;
          }
        },
        ctrl.signal
      )
        .catch((err: unknown) => {
          if (ctrl.signal.aborted) return;
          push({ kind: "err", text: err instanceof ApiError ? err.message : "Execution failed." });
        })
        .finally(() => {
          if (ctrl.signal.aborted) return;
          setRunning(null);
          setDangerAck(false);
        });
    },
    [path, running, dangerAck, engagementId, sessionId]
  );

  const providerTabs = (
    <div className="hp-adg-providers" role="tablist" aria-label="cloud provider">
      {PROVIDERS.map((pr) => (
        <button
          key={pr.id}
          type="button"
          role="tab"
          aria-selected={provider === pr.id}
          className={`hp-tn-chip${provider === pr.id ? " is-on" : ""}`}
          onClick={() => setProvider(pr.id)}
        >
          {pr.label}
        </button>
      ))}
    </div>
  );

  // The SSRF→IMDS seed panel — the web↔cloud seam, shown above the graph in every state.
  const seedPanel = (
    <CockpitCloudSeed onSeed={handleSeed} engagement={!!engagementId} autoSeed={autoSeed} />
  );

  // ---- empty state ---------------------------------------------------------- //
  if (!result) {
    return (
      <div className="hp-adg">
        {seedPanel}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">load an enumeration</div>
          <div className="hp-tn-cardsub">
            Map the route from an owned principal to an admin/owner-equivalent identity. Each edge’s
            IAM abuse is grounded in the KB and runs only through the gated executor — you approve
            every command.
          </div>
          {providerTabs}
          {error && <div className="hp-tn-error">{error}</div>}
          {warnings.length > 0 && (
            <ul className="hp-tn-bullets">
              {warnings.map((w, i) => (
                <li key={i}>⚠ {w}</li>
              ))}
            </ul>
          )}
          <div className="hp-tn-actions">
            <span className="hp-tn-actions-label">act</span>
            <button type="button" className="hp-tn-start" onClick={ingestSample} disabled={loading}>
              {loading ? "loading…" : "load the sample account (synthetic AWS)"}
            </button>
          </div>
          <p className="hp-tn-note">
            No cloud credentials needed — the sample is a synthetic AWS account with a real 3-hop
            IAM privilege-escalation route to an admin role. A live enumeration (ScoutSuite / Prowler
            / pacu / cloudfox) wires in the same way, as a gated job, when an account is in an
            engagement scope.
          </p>
        </section>
      </div>
    );
  }

  if (!path) {
    return (
      <div className="hp-adg">
        {seedPanel}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">no path found</div>
          <div className="hp-tn-cardsub">{result.reason}</div>
          <div className="hp-tn-actions">
            <span className="hp-tn-actions-label">act</span>
            <button type="button" className="hp-tn-start" onClick={ingestSample}>
              reload
            </button>
          </div>
        </section>
      </div>
    );
  }

  const startNode = nodeOf(path.node_ids[0]);
  const targetNode = nodeOf(result.target);

  return (
    <div className="hp-adg">
      {seedPanel}
      <header className="hp-adg-head">
        <div>
          <h2 className="hp-ck-title hp-ck-title-sm">
            Route to admin ({shortLabel(targetNode.label)})
          </h2>
          <p className="hp-ck-sub">
            {graphProvider ? <b>{graphProvider.toUpperCase()}</b> : "cloud"}
            {account ? (
              <>
                {" "}
                account <b>{account}</b>
              </>
            ) : null}{" "}
            · {path.length} hop{path.length === 1 ? "" : "s"} from{" "}
            <b>{shortLabel(startNode.label)}</b> to <b>{shortLabel(targetNode.label)}</b>.
            {scopeLabel && engagementId && (
              <>
                {" "}
                Walking a step runs against your scope: <code>{scopeLabel}</code>.
              </>
            )}
          </p>
        </div>
        <span className="hp-adg-count">
          {walked.size}/{path.edges.length} walked
        </span>
      </header>

      {providerTabs}

      {/* CLOUD IAM ORCHESTRATION — the agent proposes the next edge (an index); the human approves
          each one. It runs nothing itself: approval goes to the same gated executor the manual walk
          below already uses, and the walk never advances on its own. */}
      {graphId && (
        <CockpitCloudOrchestrator
          graphId={graphId}
          owned={owned}
          traversed={traversed}
          engagementId={engagementId}
          scopeLabel={scopeLabel}
          sessionId={sessionId}
          onAdvanced={(next, kind) => {
            setOwned(next.owned);
            setTraversed(next.traversed);
            const idx = path.edges.findIndex((e) => e.kind === kind);
            if (idx >= 0) setWalked((w) => new Set(w).add(idx));
          }}
        />
      )}

      {/* the route: typed nodes with abuse edges between them, igniting in sequence */}
      <div className="hp-adg-route" role="list">
        {path.node_ids.map((nid, i) => {
          const n = nodeOf(nid);
          const edge = i > 0 ? path.edges[i - 1] : null;
          const edgeIdx = i - 1;
          const done = edge ? walked.has(edgeIdx) : false;
          return (
            <NodeAndEdge
              key={nid + i}
              node={n}
              edge={edge}
              igniteAt={i}
              isTarget={nid === result.target}
              isStart={i === 0}
              done={done}
              active={running === edgeIdx}
              open={openEdge === edgeIdx}
              onOpenEdge={() => setOpenEdge(openEdge === edgeIdx ? null : edgeIdx)}
            />
          );
        })}
      </div>

      {/* edge-detail drawer: the abuse technique + KB-grounded command + walk button */}
      {openEdge !== null && path.edges[openEdge] && (
        <EdgeDrawer
          edge={path.edges[openEdge]}
          index={openEdge}
          engagement={!!engagementId}
          running={running === openEdge}
          anyRunning={running !== null}
          walked={walked.has(openEdge)}
          dangerAck={dangerAck}
          onDangerAck={setDangerAck}
          onWalk={(tech) => walk(openEdge, tech)}
          onClose={() => setOpenEdge(null)}
        />
      )}

      {/* live / last output */}
      {lines.length > 0 && (
        <section className="hp-ck-out-wrap hp-adg-out">
          <div className="hp-ck-out-bar">
            <span className="hp-ck-out-lights" aria-hidden>
              <i />
              <i />
              <i />
            </span>
            <span className="hp-ck-out-title">
              {running !== null ? "abuse step · streaming" : "abuse step · last run"}
            </span>
            {exitCode !== null && (
              <span className={exitCode === 0 ? "hp-ck-exit0" : "hp-ck-exitn"}>exit {exitCode}</span>
            )}
          </div>
          <div className="hp-ck-out" ref={outRef}>
            {lines.map((l, i) => (
              <div key={i} className={`hp-ck-line hp-ck-${l.kind}`}>
                {l.text || " "}
              </div>
            ))}
            {running !== null && (
              <div className="hp-ck-line hp-ck-cursor" aria-hidden>
                ▋
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
}

/** Split a one-line command into argv tokens (quote-aware). Multi-line commands use the first
 *  runnable line. Not a shell — the executor runs argv-only. */
function tokenize(cmd: string): string[] {
  const line = (cmd.split("\n").find((l) => l.trim() && !l.trim().startsWith("#")) ?? "").trim();
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3] ?? "");
  return out;
}

function NodeAndEdge({
  node,
  edge,
  igniteAt,
  isTarget,
  isStart,
  done,
  active,
  open,
  onOpenEdge,
}: {
  node: CloudNode;
  edge: CloudPathEdge | null;
  igniteAt: number;
  isTarget: boolean;
  isStart: boolean;
  done: boolean;
  active: boolean;
  open: boolean;
  onOpenEdge: () => void;
}) {
  return (
    <div className="hp-adg-seg" role="listitem">
      {edge && (
        <button
          type="button"
          className={`hp-adg-edge${done ? " is-done" : ""}${active ? " is-active" : ""}${
            open ? " is-open" : ""
          }`}
          onClick={onOpenEdge}
          title="Show the abuse technique for this edge"
        >
          <motion.span
            className="hp-adg-edge-line"
            initial={{ scaleX: 0, opacity: 0.2 }}
            animate={{ scaleX: 1, opacity: 1 }}
            transition={{ delay: igniteAt * IGNITE_STEP, duration: IGNITE_DUR, ease: "easeOut" }}
          />
          <span className="hp-adg-edge-label">{edge.kind}</span>
        </button>
      )}
      <motion.div
        className={`hp-adg-node is-${node.type}${isTarget ? " is-target" : ""}${
          isStart ? " is-start" : ""
        }${node.high_value ? " is-hv" : ""}`}
        initial={{ opacity: 0, y: 8, scale: 0.9 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ delay: igniteAt * IGNITE_STEP + 0.08, duration: 0.3 }}
      >
        <span className="hp-adg-node-icon" aria-hidden>
          {NODE_ICON[node.type] ?? "•"}
        </span>
        <span className="hp-adg-node-label">{shortLabel(node.label)}</span>
        {isStart && <span className="hp-adg-tag">owned</span>}
        {isTarget && <span className="hp-adg-tag is-target">admin / owner</span>}
      </motion.div>
    </div>
  );
}

function EdgeDrawer({
  edge,
  index,
  engagement,
  running,
  anyRunning,
  walked,
  dangerAck,
  onDangerAck,
  onWalk,
  onClose,
}: {
  edge: CloudPathEdge;
  index: number;
  engagement: boolean;
  running: boolean;
  anyRunning: boolean;
  walked: boolean;
  dangerAck: boolean;
  onDangerAck: (v: boolean) => void;
  onWalk: (tech: CloudTechnique) => void;
  onClose: () => void;
}) {
  const tech = edge.technique;
  if (!tech) return null;
  const cmd = tech.commands[0]?.cmd ?? "";
  return (
    <motion.section
      className={`hp-adg-drawer${tech.destructive ? " is-destructive" : ""}`}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      <div className="hp-adg-drawer-head">
        <span className="hp-adg-drawer-hop">
          hop {index + 1}: <b>{edge.kind}</b>
        </span>
        <span className={tech.grounded ? "hp-adg-badge is-grounded" : "hp-adg-badge is-ai"}>
          {tech.grounded ? `grounded · ${tech.entry_title ?? "KB"}` : "ai-suggested"}
        </span>
        {tech.destructive && <span className="hp-adg-badge is-destr">destructive</span>}
        <button type="button" className="hp-adg-drawer-x" onClick={onClose} aria-label="Close">
          ✕
        </button>
      </div>

      <p className="hp-adg-drawer-title">{tech.title}</p>
      <p className="hp-adg-drawer-summary">{tech.summary}</p>
      {tech.entry_id && (
        <a
          className="hp-adg-drawer-cite"
          href={`/entry/${tech.entry_id}`}
          target="_blank"
          rel="noreferrer"
        >
          KB: {tech.entry_title} →
        </a>
      )}

      <pre className="hp-adg-cmd">{cmd}</pre>

      {tech.destructive && (
        <div className="hp-adg-danger" role="alert">
          <p className="hp-adg-danger-head">⚠ this is a real, high-impact change on the account</p>
          <p className="hp-adg-danger-note">
            {engagement
              ? "The sandbox is FULLY OPEN and the account is real — this attaches an admin policy, mints credentials, or overwrites code. Approving is a deliberate act."
              : "Runs against the isolated lab — but approving is a conscious choice, not an accident."}
          </p>
          <label className="hp-adg-danger-ack">
            <input type="checkbox" checked={dangerAck} onChange={(e) => onDangerAck(e.target.checked)} />
            <span>
              {engagement
                ? "Yes, run this against the real, authorized account."
                : "Yes, run this against the isolated lab."}
            </span>
          </label>
        </div>
      )}

      <div className="hp-adg-drawer-actions">
        <button
          type="button"
          className={`hp-ck-approve${tech.destructive ? " is-danger" : ""}`}
          disabled={anyRunning || (tech.destructive && !dangerAck) || !cmd}
          onClick={() => onWalk(tech)}
          title={
            tech.destructive && !dangerAck
              ? "Confirm the destructive action above to enable approval"
              : "Approve and run this abuse step through the gated executor"
          }
        >
          {running
            ? "running…"
            : walked
              ? "walk again"
              : tech.destructive
                ? "APPROVE (DESTRUCTIVE) & WALK"
                : "APPROVE & WALK THIS EDGE"}
        </button>
        {walked && <span className="hp-adg-walked-tag">✓ walked</span>}
      </div>
      <p className="hp-adg-drawer-foot">
        Runs through the gated executor — argv-only, {engagement ? "engagement scope-locked" : "isolated lab"},
        approve-each. The graph never runs anything on its own.
      </p>

      {/* The same hop, from the DEFENDER's chair: the ATT&CK technique this abuse maps to, the
          CloudTrail/activity-log events it throws, and the public rule that would catch it. */}
      {cmd && (
        <div className="hp-det-row">
          <DetectionDisclosure
            source={{ kind: "argv", argv: cmd, context: `Cloud IAM abuse: ${edge.kind}` }}
            heading={`If this hop ran: ${edge.source_label} —${edge.kind}→ ${edge.target_label}`}
          />
        </div>
      )}
    </motion.section>
  );
}
