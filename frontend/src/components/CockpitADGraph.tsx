"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { CockpitADOrchestrator } from "./CockpitADOrchestrator";
import { CockpitADPersistence } from "./CockpitADPersistence";
import { DetectionDisclosure } from "./DetectionPanel";
import {
  ApiError,
  adComputePath,
  adGetGraph,
  adIngest,
  execCockpitStream,
  type ADNode,
  type ADPathEdge,
  type ADPathResult,
  type ADTechnique,
  type ExecEvent,
} from "@/lib/api";

/**
 * The AD attack-path graph — the route from an owned low-priv principal to Domain Admin,
 * rendered in the cockpit's kill-chain cinematic style: typed nodes ignite in sequence along
 * the route, each edge is labeled with its abuse, and clicking an edge opens a drawer with the
 * KB-grounded technique + the concrete command.
 *
 * WALK THE PATH: from the drawer the human can send an edge's abuse command to the SAME gated
 * executor every cockpit command uses (approve-each; engagement scope-locked to the AD hosts;
 * heuristic red-confirm). Running a step marks the edge traversed and lights the next hop. It
 * NEVER auto-runs — every step is an explicit human approval. In engagement-loop mode the agent
 * may propose the next edge, but the human still approves each. This component only proposes +
 * streams the gated executor; it has no other way to run anything.
 */

const IGNITE_STEP = 0.14;
const IGNITE_DUR = 0.44;

type Line = { kind: "stdout" | "stderr" | "meta" | "err"; text: string };

const NODE_ICON: Record<ADNode["type"], string> = {
  user: "👤",
  group: "👥",
  computer: "🖥️",
  domain: "🌐",
  ou: "🗂️",
  gpo: "📜",
  container: "📦",
  certtemplate: "📄",
  certauthority: "🏛️",
};

function shortLabel(label: string): string {
  // USER@DOMAIN → USER ; DN → first CN ; else as-is
  const at = label.split("@")[0];
  if (at.toUpperCase().startsWith("CN=")) return at.slice(3).split(",")[0];
  return at;
}

export function CockpitADGraph({
  sessionId = null,
  engagementId = null,
  scopeLabel = null,
}: {
  sessionId?: string | null;
  /** When set, walking a step runs in REAL-TARGET engagement mode against this engagement
   *  (routing through _validate_engagement: target → approval → danger). Omit → lab mode. */
  engagementId?: string | null;
  scopeLabel?: string | null;
}) {
  const [graphId, setGraphId] = useState<string | null>(null);
  const [domain, setDomain] = useState<string | null>(null);
  // ORCHESTRATION STATE — which principals the operator controls and which edges are walked.
  // Held here so the agent's proposals and the rendered path stay in step.
  const [owned, setOwned] = useState<string[]>([]);
  const [traversed, setTraversed] = useState<string[]>([]);
  const [nodes, setNodes] = useState<Map<string, ADNode>>(new Map());
  const [result, setResult] = useState<ADPathResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);

  // the edge whose detail drawer is open (index into the best path)
  const [openEdge, setOpenEdge] = useState<number | null>(null);
  // edges the human has walked (traversed) — light them "done"
  const [walked, setWalked] = useState<Set<number>>(new Set());

  // walk-the-path exec stream
  const [running, setRunning] = useState<number | null>(null);
  const [dangerAck, setDangerAck] = useState(false);
  const [lines, setLines] = useState<Line[]>([]);
  const [exitCode, setExitCode] = useState<number | null>(null);
  const ctrlRef = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => () => ctrlRef.current?.abort(), []);
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [lines]);

  const path = result?.found ? result.path : null;

  const ingestSample = useCallback(async (startOverride?: string, ownedOverride?: string[]) => {
    const start = startOverride ?? SAMPLE_START;
    setLoading(true);
    setError(null);
    setResult(null);
    setWalked(new Set());
    setOpenEdge(null);
    try {
      // The sample ingest folds in the synthetic vulnerable-CA (certipy) data too, so the graph
      // carries the ESC route as well as the classic ACL chain.
      const ing = await adIngest({ use_sample: true, session_id: sessionId });
      setGraphId(ing.graph_id);
      setDomain(ing.domain);
      // ownedOverride lets the unconstrained-delegation demo pre-own the delegation host + the DA
      // objective so the persistence panel renders golden + silver UNLOCKED. The route is still
      // computed from `start`, so the TrustedForDelegation chain shows regardless.
      setOwned(ownedOverride ?? [start]);
      setTraversed([]);
      setWarnings(ing.warnings);
      // compute the route to DA from the owned start (TYWIN = ACL chain; HODOR = ESC chain) +
      // load the node map for icons
      const [pathRes, g] = await Promise.all([
        adComputePath({ graph_id: ing.graph_id, start, with_techniques: true }),
        adGetGraph(ing.graph_id),
      ]);
      const nm = new Map<string, ADNode>();
      for (const n of g.nodes) nm.set(n.id, n);
      // mark the start as owned for the UI
      const s = nm.get(start);
      if (s) nm.set(start, { ...s, owned: true });
      setNodes(nm);
      setResult(pathRes);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Couldn’t load the AD graph.");
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  // Deep-link auto-load (the ?demo= pattern) so the headless screenshot renders without a click:
  //   ?demo=esc → the AD CS ESC route from a low-priv enrollee (HODOR) through a vulnerable
  //   template to Domain Admins;  ?demo=1 → the classic ACL chain from TYWIN.
  // The ingest runs in a deferred callback (setTimeout), never the effect body, so the initial
  // setState stays off the effect's synchronous path and the lint baseline is unchanged.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const demo = new URLSearchParams(window.location.search).get("demo");
    if (!demo) return;
    // ?demo=deleg → the unconstrained-delegation route (PODRICK → AdminTo → APP01 →
    // TrustedForDelegation → Domain Admins) with golden/silver persistence unlocked;
    // ?demo=esc → the AD CS ESC route; ?demo=1 → the classic ACL chain.
    const start =
      demo === "esc" ? ESC_SAMPLE_START : demo === "deleg" ? DELEG_SAMPLE_START : SAMPLE_START;
    const ownedOverride = demo === "deleg" ? DELEG_DEMO_OWNED : undefined;
    const id = window.setTimeout(() => void ingestSample(start, ownedOverride), 0);
    return () => window.clearTimeout(id);
  }, [ingestSample]);

  const nodeOf = useCallback(
    (id: string): ADNode =>
      nodes.get(id) ?? { id, type: "container", label: id, high_value: false, owned: false, props: {} },
    [nodes]
  );

  const walk = useCallback(
    (idx: number, tech: ADTechnique) => {
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
              // mark this edge traversed regardless of exit — the human ran it
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

  // ---- empty state ---------------------------------------------------------- //
  if (!result) {
    return (
      // D9: the empty state is a plain card now, in the house vocabulary. The GRAPH itself
      // keeps its own hp-adg-* primitives — those have no hp-tn-* equivalent and rewriting a
      // working canvas is not a restyle.
      <div className="hp-adg">
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">load a collection</div>
          <div className="hp-tn-cardsub">
            Map the route from an owned low-priv user to Domain Admin. Each edge’s abuse is
            grounded in the KB and runs only through the gated executor — you approve every
            command.
          </div>
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
            <button
              type="button"
              className="hp-tn-start"
              onClick={() => ingestSample()}
              disabled={loading}
            >
              {loading ? "loading…" : "load the sample domain (GOAD-style)"}
            </button>
          </div>
          {/* `hp-tn-note`, NOT `hp-tn-olhint`. The latter is a LABEL style — 10px, 1px
              letter-spacing, ALL CAPS, and a bottom margin with no top one — which is right
              for "expected:" or "path" and wrong for three lines of prose: it comes out
              unreadable and crammed against the row above. */}
          <p className="hp-tn-note">
            No AD lab needed — the sample is a synthetic domain with a real 5-hop route to Domain
            Admins. A live collection (bloodhound-python) wires in the same way, through the gated
            executor, when a domain is in scope.
          </p>
        </section>
      </div>
    );
  }

  if (!path) {
    return (
      <div className="hp-adg">
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">no path found</div>
          <div className="hp-tn-cardsub">{result.reason}</div>
          <div className="hp-tn-actions">
            <span className="hp-tn-actions-label">act</span>
            <button type="button" className="hp-tn-start" onClick={() => ingestSample()}>
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
      <header className="hp-adg-head">
        <div>
          <h2 className="hp-ck-title hp-ck-title-sm">Route to Domain Admin</h2>
          <p className="hp-ck-sub">
            {domain ? <b>{domain}</b> : "AD graph"} · {path.length} hop
            {path.length === 1 ? "" : "s"} from{" "}
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

      {/* AD ORCHESTRATION — the agent proposes the next edge; the human approves each one.
          It runs nothing itself: approval goes to the same gated executor the manual walk
          below already uses, and the walk never advances on its own. */}
      {graphId && (
        <CockpitADOrchestrator
          graphId={graphId}
          owned={owned}
          traversed={traversed}
          engagementId={engagementId}
          scopeLabel={scopeLabel}
          sessionId={sessionId}
          onAdvanced={(next, kind) => {
            setOwned(next.owned);
            setTraversed(next.traversed);
            // light the matching hop on the rendered route, if this edge is on it
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
              <span className={exitCode === 0 ? "hp-ck-exit0" : "hp-ck-exitn"}>
                exit {exitCode}
              </span>
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

      {/* POST-COMPROMISE PERSISTENCE — golden / silver ticket forging. A distinct panel, not a
          route hop: it is offered only once you hold the secret (krbtgt / a service hash) and is
          never part of the path search or the orchestrator frontier. */}
      {graphId && (
        <CockpitADPersistence
          graphId={graphId}
          owned={owned}
          traversed={traversed}
          engagement={!!engagementId}
        />
      )}
    </div>
  );
}

// The sample's owned start principal (TYWIN's SID) — matches sample_data.py.
const SAMPLE_START = "S-1-5-21-1111111111-2222222222-3333333333-1104";
// The AD CS demo's owned start (HODOR's SID) — a low-priv enrollee who reaches DA via the ESC
// chain (ESC4 rewrite → ESC1). Matches sample_data.ESC_SAMPLE_START.
const ESC_SAMPLE_START = "S-1-5-21-1111111111-2222222222-3333333333-1110";
// The unconstrained-delegation demo's owned start (PODRICK's SID) — local admin on APP01, which is
// trusted for delegation. Matches sample_data.DELEG_SAMPLE_START.
const DELEG_SAMPLE_START = "S-1-5-21-1111111111-2222222222-3333333333-1112";
// PODRICK + APP01 (the delegation host) + Domain Admins — pre-owned in the deleg demo so the
// persistence panel renders golden (krbtgt held) + silver (APP01's hash held) unlocked. Matches
// sample_data.DELEG_DEMO_OWNED.
const DELEG_DEMO_OWNED = [
  "S-1-5-21-1111111111-2222222222-3333333333-1112",
  "S-1-5-21-1111111111-2222222222-3333333333-1131",
  "S-1-5-21-1111111111-2222222222-3333333333-512",
];

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
  node: ADNode;
  edge: ADPathEdge | null;
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
        {isTarget && <span className="hp-adg-tag is-target">Domain Admin</span>}
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
  edge: ADPathEdge;
  index: number;
  engagement: boolean;
  running: boolean;
  anyRunning: boolean;
  walked: boolean;
  dangerAck: boolean;
  onDangerAck: (v: boolean) => void;
  onWalk: (tech: ADTechnique) => void;
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
        <a className="hp-adg-drawer-cite" href={`/entry/${tech.entry_id}`} target="_blank" rel="noreferrer">
          KB: {tech.entry_title} →
        </a>
      )}

      <pre className="hp-adg-cmd">{cmd}</pre>

      {tech.destructive && (
        <div className="hp-adg-danger" role="alert">
          <p className="hp-adg-danger-head">
            ⚠ this is a real, high-impact change on the domain
          </p>
          <p className="hp-adg-danger-note">
            {engagement
              ? "The sandbox is FULLY OPEN and the target is real — this resets a password, edits a DACL, adds a member, or replicates secrets. Approving is a deliberate act."
              : "Runs against the isolated lab — but approving is a conscious choice, not an accident."}
          </p>
          <label className="hp-adg-danger-ack">
            <input
              type="checkbox"
              checked={dangerAck}
              onChange={(e) => onDangerAck(e.target.checked)}
            />
            <span>
              {engagement
                ? "Yes, run this against the real, authorized target."
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
          directory/host events it throws, and the public rule that would catch it. Purely
          descriptive — it changes nothing about the command above. */}
      {cmd && (
        <div className="hp-det-row">
          <DetectionDisclosure
            source={{ kind: "argv", argv: cmd, context: `Active Directory abuse: ${edge.kind}` }}
            heading={`If this hop ran: ${edge.source_label} —${edge.kind}→ ${edge.target_label}`}
          />
        </div>
      )}
    </motion.section>
  );
}
