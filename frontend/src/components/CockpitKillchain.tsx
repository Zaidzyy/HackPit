"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { DetectionDisclosure } from "./DetectionPanel";
import {
  ApiError,
  execCockpitStream,
  getKillchainAlternative,
  killchainAdvance,
  killchainGraph,
  killchainPropose,
  type ExecEvent,
  type KillchainGraphResult,
  type KillchainNode,
  type KillchainPathEdge,
  type KillchainProposal,
  type KillchainTechnique,
} from "@/lib/api";
import { AlternativeDisclosure } from "./AlternativeDisclosure";

/**
 * The cross-domain KILL-CHAIN graph — the capstone that stitches the web foothold, cloud IAM and
 * on-prem AD graphs into ONE routed chain, rendered as three swim-lanes with the stitched path lit
 * across them. Cross-domain SEAMS (SSRF→IMDS, cloud-creds→AD, web-RCE→host) are the pivots that
 * carry the route from one lane to the next.
 *
 * READ-AND-STITCH: this overlay reads each graph's public output; it never runs anything on its own.
 * The agent may PROPOSE the next edge (an index into the real frontier). A CROSS-DOMAIN hop is
 * approved and sent to the SAME gated executor every cockpit command uses (approve-each,
 * scope-locked, heuristic red-confirm); a WITHIN-LANE hop is approved in its own :cloud / :ad-graph
 * view (single source of truth for per-lane abuse). It never auto-runs.
 */

const IGNITE_STEP = 0.1;

type Line = { kind: "stdout" | "stderr" | "meta" | "err"; text: string };

const LANES: { id: "web" | "cloud" | "onprem"; label: string; kicker: string }[] = [
  { id: "web", label: "web", kicker: "foothold" },
  { id: "cloud", label: "cloud", kicker: "IAM" },
  { id: "onprem", label: "on-prem", kicker: "Active Directory" },
];

const NODE_ICON: Record<string, string> = {
  finding: "🎯",
  user: "👤",
  role: "🎭",
  group: "👥",
  serviceaccount: "🤖",
  computer: "🖥️",
  domain: "🏛️",
  secret: "🔑",
  bucket: "🪣",
  function: "⚡",
  kmskey: "🗝️",
  policy: "📜",
  account: "☁️",
  certtemplate: "📄",
  certauthority: "🏢",
  resource: "📦",
};

/** A readable name from an ARN / SID / URL label — the last path or `:` segment. */
function shortLabel(label: string): string {
  const at = label.split("@")[0];
  const tail = at.split(":").pop() ?? at;
  return tail.split("/").pop() || label;
}

function tokenize(cmd: string): string[] {
  const line = (cmd.split("\n").find((l) => l.trim() && !l.trim().startsWith("#")) ?? "").trim();
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3] ?? "");
  return out;
}

export function CockpitKillchain({
  sessionId = null,
  engagementId = null,
  scopeLabel = null,
}: {
  sessionId?: string | null;
  engagementId?: string | null;
  scopeLabel?: string | null;
}) {
  const [data, setData] = useState<KillchainGraphResult | null>(null);
  const [nodes, setNodes] = useState<Map<string, KillchainNode>>(new Map());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [openEdge, setOpenEdge] = useState<number | null>(null);
  const [walked, setWalked] = useState<Set<number>>(new Set());

  // orchestrator proposal
  const [proposing, setProposing] = useState(false);
  const [proposal, setProposal] = useState<KillchainProposal | null>(null);
  const [proposeNote, setProposeNote] = useState<string | null>(null);

  // walk-the-seam exec stream
  const [running, setRunning] = useState<number | null>(null);
  const [dangerAck, setDangerAck] = useState(false);
  const [lines, setLines] = useState<Line[]>([]);
  const [exitCode, setExitCode] = useState<number | null>(null);
  const ctrlRef = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);
  const autoloaded = useRef(false);

  useEffect(() => () => ctrlRef.current?.abort(), []);
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [lines]);

  const demoDefault = sessionId == null;

  const load = useCallback(
    async (demo: boolean) => {
      setLoading(true);
      setError(null);
      setProposal(null);
      setWalked(new Set());
      setOpenEdge(null);
      try {
        const res = await killchainGraph({ demo, session_id: sessionId });
        const nm = new Map<string, KillchainNode>();
        for (const n of res.graph.nodes) nm.set(n.id, n);
        setNodes(nm);
        setData(res);
      } catch (err: unknown) {
        setError(err instanceof ApiError ? err.message : "Couldn’t load the kill-chain graph.");
      } finally {
        setLoading(false);
      }
    },
    [sessionId]
  );

  // Deep-link auto-load so the headless-Edge screenshot renders content, not the empty state.
  // ?demo=1 → the synthetic three-lane chain. setState lives inside load()'s async body (not this
  // effect), keeping the hooks lint at baseline (frontend/AGENTS.md).
  useEffect(() => {
    if (autoloaded.current) return;
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    if (params.has("demo") || sessionId == null) {
      autoloaded.current = true;
      // Deep-link auto-load: setState lives in load()'s async body, but Next 16's
      // set-state-in-effect flags calling a setState-carrying callback from an effect regardless.
      // Deliberate — keep the counted lint baseline at 11 (frontend/AGENTS.md).
      // eslint-disable-next-line react-hooks/set-state-in-effect
      void load(true);
    }
  }, [load, sessionId]);

  const nodeOf = useCallback(
    (id: string): KillchainNode =>
      nodes.get(id) ?? {
        id,
        type: "resource",
        label: id,
        domain: "",
        high_value: false,
        owned: false,
        props: {},
      },
    [nodes]
  );

  const route = data?.route?.found ? data.route.path : null;

  const propose = useCallback(async () => {
    if (!data) return;
    setProposing(true);
    setProposeNote(null);
    try {
      const owned = data.start ? [data.start] : data.graph.nodes.filter((n) => n.owned).map((n) => n.id);
      const res = await killchainPropose({
        demo: demoDefault,
        session_id: sessionId,
        owned,
        goal: data.goal,
        engagement_id: engagementId ?? undefined,
      });
      setProposal(res.proposal);
      setProposeNote(res.proposal ? res.note : res.reason || "The agent proposed no further edge.");
      if (res.proposal && route) {
        const idx = route.edges.findIndex(
          (e) =>
            e.source === res.proposal!.edge.source &&
            e.target === res.proposal!.edge.target &&
            e.kind === res.proposal!.edge.kind
        );
        if (idx >= 0) setOpenEdge(idx);
      }
    } catch (err: unknown) {
      setProposeNote(err instanceof ApiError ? err.message : "The proposer is unavailable.");
    } finally {
      setProposing(false);
    }
  }, [data, demoDefault, sessionId, engagementId, route]);

  const walk = useCallback(
    (idx: number, tech: KillchainTechnique) => {
      if (!route || running !== null) return;
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
          approved: true,
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
              if (ev.code === 0) setWalked((w) => new Set(w).add(idx));
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
    [route, running, dangerAck, engagementId, sessionId]
  );

  // ---- empty state ---------------------------------------------------------- //
  if (!data) {
    return (
      <div className="hp-kc">
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">stitch the kill chain</div>
          <div className="hp-tn-cardsub">
            One view over three graphs: a web foothold, the cloud IAM graph, and the on-prem AD graph,
            joined by the cross-domain seams (SSRF→cloud metadata, cloud secret→AD credential, web
            RCE→host). The agent picks an EDGE, never a command — a seam crossing runs only through the
            gated executor, a within-lane hop in its own view.
          </div>
          {error && <div className="hp-tn-error">{error}</div>}
          <div className="hp-tn-actions">
            <span className="hp-tn-actions-label">act</span>
            <button type="button" className="hp-tn-start" onClick={() => load(true)} disabled={loading}>
              {loading ? "loading…" : "load the synthetic three-lane kill chain"}
            </button>
          </div>
          <p className="hp-tn-note">
            No live data needed — the sample stitches a synthetic web→cloud→on-prem chain to Domain
            Admin. Live lanes wire in from :recon/:proxy (web), :cloud, and :ad-graph as an engagement
            fills them.
          </p>
        </section>
      </div>
    );
  }

  const stepIds = route ? route.node_ids : [];
  const laneOf = (id: string) => nodeOf(id).domain || "web";

  return (
    <div className="hp-kc">
      {/* summary */}
      <header className="hp-kc-summary">
        <div>
          <h2 className="hp-ck-title hp-ck-title-sm">
            {route ? (
              <>
                Kill chain to <b>{shortLabel(data.route.target_label ?? "objective")}</b>
              </>
            ) : (
              "Merged three-lane graph"
            )}
          </h2>
          <p className="hp-ck-sub">
            {route ? (
              <>
                {route.length} hop{route.length === 1 ? "" : "s"} from{" "}
                <b>{shortLabel(data.route.start_label ?? "foothold")}</b> across{" "}
                <b>
                  {route.crossings} lane crossing{route.crossings === 1 ? "" : "s"}
                </b>{" "}
                — web → cloud → on-prem.
                {scopeLabel && engagementId && (
                  <>
                    {" "}
                    Walking a seam runs against your scope: <code>{scopeLabel}</code>.
                  </>
                )}
              </>
            ) : (
              data.route.reason
            )}
          </p>
        </div>
        <div className="hp-kc-stats">
          <span className="hp-kc-stat">
            <b>{data.graph.stats.nodes ?? 0}</b> nodes
          </span>
          <span className="hp-kc-stat">
            <b>{data.graph.stats.bridge_edges ?? 0}</b> seams
          </span>
          <span className="hp-kc-stat">
            {walked.size}/{route ? route.edges.length : 0} walked
          </span>
        </div>
      </header>

      {data.graph.warnings.length > 0 && (
        <ul className="hp-tn-bullets">
          {data.graph.warnings.slice(0, 4).map((w, i) => (
            <li key={i}>⚠ {w}</li>
          ))}
        </ul>
      )}

      {/* THE SWIM LANES — three bands (web / cloud / on-prem); each route node sits in its lane at
          its step column, so the path visibly descends across the lanes as it advances. */}
      {route && (
        <div className="hp-kc-board">
          {LANES.map((lane) => (
            <div key={lane.id} className={`hp-kc-lanerow is-${lane.id}`} role="row">
              <div className="hp-kc-lanelabel">
                <span className="hp-kc-lanelabel-name">{lane.label}</span>
                <span className="hp-kc-lanelabel-kicker">{lane.kicker}</span>
              </div>
              <div
                className="hp-kc-track"
                style={{ gridTemplateColumns: `repeat(${stepIds.length}, minmax(108px, 1fr))` }}
              >
                {stepIds.map((nid, i) => {
                  const inLane = laneOf(nid) === lane.id;
                  const edge = i > 0 ? route.edges[i - 1] : null;
                  const edgeIdx = i - 1;
                  if (!inLane) return <div key={nid + i} className="hp-kc-cell is-empty" />;
                  const n = nodeOf(nid);
                  return (
                    <div key={nid + i} className="hp-kc-cell">
                      {edge && (
                        <button
                          type="button"
                          className={`hp-kc-edgelabel${edge.bridge ? " is-seam" : ""}${
                            walked.has(edgeIdx) ? " is-done" : ""
                          }${openEdge === edgeIdx ? " is-open" : ""}${
                            running === edgeIdx ? " is-active" : ""
                          }`}
                          onClick={() => setOpenEdge(openEdge === edgeIdx ? null : edgeIdx)}
                          title={edge.bridge ? "Cross-domain seam — click for the crossing" : "Click for this hop"}
                        >
                          {edge.bridge ? "⇄ " : ""}
                          {edge.kind}
                        </button>
                      )}
                      <motion.div
                        className={`hp-kc-node is-${n.type}${n.high_value ? " is-hv" : ""}${
                          n.owned || i === 0 ? " is-owned" : ""
                        }${nid === data.route.target ? " is-target" : ""}`}
                        initial={{ opacity: 0, y: 6, scale: 0.92 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        transition={{ delay: i * IGNITE_STEP + 0.05, duration: 0.3 }}
                      >
                        <span className="hp-kc-node-icon" aria-hidden>
                          {NODE_ICON[n.type] ?? "•"}
                        </span>
                        <span className="hp-kc-node-label">{shortLabel(n.label)}</span>
                        {(n.owned || i === 0) && <span className="hp-kc-node-tag">foothold</span>}
                        {nid === data.route.target && (
                          <span className="hp-kc-node-tag is-target">objective</span>
                        )}
                      </motion.div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* orchestrator: propose the next edge (an index into the real frontier) */}
      <section className="hp-kc-orch">
        <div className="hp-kc-orch-head">
          <span className="hp-kc-orch-title">agent · propose the next edge</span>
          <button type="button" className="hp-tn-chip is-on" onClick={propose} disabled={proposing || !route}>
            {proposing ? "thinking…" : "propose next edge"}
          </button>
        </div>
        {proposeNote && <p className="hp-kc-orch-note">{proposeNote}</p>}
        {proposal && (
          <p className="hp-kc-orch-pick">
            → <b>{proposal.edge.kind}</b>{" "}
            {proposal.is_bridge ? (
              <span className="hp-kc-seamchip">
                seam {proposal.edge.domain_from}→{proposal.edge.domain_to}
              </span>
            ) : (
              <span className="hp-kc-lanechip">within {proposal.edge.domain_from}</span>
            )}{" "}
            — {proposal.rationale}
          </p>
        )}
      </section>

      {/* per-hop drawer: the technique + (seam → approve&cross; within-lane → open its view) */}
      {openEdge !== null && route && route.edges[openEdge] && (
        <HopDrawer
          edge={route.edges[openEdge]}
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
        <section className="hp-ck-out-wrap hp-kc-out">
          <div className="hp-ck-out-bar">
            <span className="hp-ck-out-lights" aria-hidden>
              <i />
              <i />
              <i />
            </span>
            <span className="hp-ck-out-title">
              {running !== null ? "seam crossing · streaming" : "seam crossing · last run"}
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

      {/* lane overview — every node in each lane, so the three stitched graphs are visible in full */}
      <div className="hp-kc-overview">
        {LANES.map((lane) => {
          const laneNodes = data.graph.nodes.filter((n) => (n.domain || "web") === lane.id);
          return (
            <section key={lane.id} className={`hp-kc-lanecard is-${lane.id}`}>
              <div className="hp-kc-lanecard-head">
                <span className="hp-kc-lanecard-name">{lane.label}</span>
                <span className="hp-kc-lanecard-count">{laneNodes.length}</span>
              </div>
              <div className="hp-kc-lanecard-nodes">
                {laneNodes.map((n) => (
                  <span
                    key={n.id}
                    className={`hp-kc-chip${n.high_value ? " is-hv" : ""}${n.owned ? " is-owned" : ""}`}
                    title={n.label}
                  >
                    <span aria-hidden>{NODE_ICON[n.type] ?? "•"}</span> {shortLabel(n.label)}
                  </span>
                ))}
                {laneNodes.length === 0 && <span className="hp-kc-chip is-empty">no nodes</span>}
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}

function HopDrawer({
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
  edge: KillchainPathEdge;
  index: number;
  engagement: boolean;
  running: boolean;
  anyRunning: boolean;
  walked: boolean;
  dangerAck: boolean;
  onDangerAck: (v: boolean) => void;
  onWalk: (tech: KillchainTechnique) => void;
  onClose: () => void;
}) {
  const tech = edge.technique;
  if (!tech) return null;
  const cmd = tech.commands[0]?.cmd ?? "";
  const isSeam = edge.bridge;
  const laneView =
    tech.domain_from === "cloud"
      ? "/cockpit/cloud"
      : tech.domain_from === "onprem"
        ? "/cockpit/ad"
        : "/cockpit/proxy";
  return (
    <motion.section
      className={`hp-adg-drawer${tech.destructive ? " is-destructive" : ""}${isSeam ? " hp-kc-drawer-seam" : ""}`}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      <div className="hp-adg-drawer-head">
        <span className="hp-adg-drawer-hop">
          hop {index + 1}: <b>{edge.kind}</b>
        </span>
        {isSeam ? (
          <span className="hp-kc-seamchip">
            seam {tech.domain_from}→{tech.domain_to}
          </span>
        ) : (
          <span className="hp-kc-lanechip">within {tech.domain_from}</span>
        )}
        {tech.attack_id && <span className="hp-kc-attackbadge">{tech.attack_id}</span>}
        {isSeam &&
          (tech.grounded ? (
            <span className="hp-adg-badge is-grounded">grounded · {tech.entry_title ?? "KB"}</span>
          ) : (
            <span className="hp-adg-badge is-ai">catalog</span>
          ))}
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

      {isSeam ? (
        <>
          <pre className="hp-adg-cmd">{cmd}</pre>
          {cmd && (
            <AlternativeDisclosure
              fetcher={() =>
                getKillchainAlternative({
                  title: tech.title,
                  cmd,
                  entry_id: tech.entry_id ?? "",
                  context: `seam ${tech.domain_from}→${tech.domain_to}: ${edge.kind}`,
                })
              }
            />
          )}
          {tech.destructive && (
            <div className="hp-adg-danger" role="alert">
              <p className="hp-adg-danger-head">⚠ this crossing establishes control on the far side</p>
              <p className="hp-adg-danger-note">
                {engagement
                  ? "The sandbox is FULLY OPEN and the target is real — this authenticates or executes across the seam. Approving is a deliberate act."
                  : "Runs against the isolated lab — but approving is a conscious choice, not an accident."}
              </p>
              <label className="hp-adg-danger-ack">
                <input type="checkbox" checked={dangerAck} onChange={(e) => onDangerAck(e.target.checked)} />
                <span>
                  {engagement
                    ? "Yes, cross this seam against the real, authorized target."
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
                  ? "Confirm the crossing above to enable approval"
                  : "Approve and cross this seam through the gated executor"
              }
            >
              {running
                ? "crossing…"
                : walked
                  ? "cross again"
                  : tech.destructive
                    ? "APPROVE (DESTRUCTIVE) & CROSS"
                    : "APPROVE & CROSS THIS SEAM"}
            </button>
            {walked && <span className="hp-adg-walked-tag">✓ crossed</span>}
          </div>
          <p className="hp-adg-drawer-foot">
            Runs through the gated executor — argv-only, {engagement ? "engagement scope-locked" : "isolated lab"},
            approve-each. The kill chain never runs anything on its own.
          </p>
          {cmd && (
            <div className="hp-det-row">
              <DetectionDisclosure
                source={{ kind: "argv", argv: cmd, context: `Cross-domain seam: ${edge.kind}` }}
                heading={`If this seam crossed: ${edge.source_label} —${edge.kind}→ ${edge.target_label}`}
              />
            </div>
          )}
        </>
      ) : (
        <div className="hp-kc-laneview">
          <p className="hp-kc-laneview-note">
            This hop is a move <b>inside the {tech.domain_from} lane</b>. Its exact abuse — the
            KB-grounded command and its red-confirm — is owned by that lane&apos;s dedicated view, so
            there is one source of truth and no drifting copy here. Resolve and approve it there.
          </p>
          <a className="hp-tn-start hp-kc-laneview-link" href={laneView}>
            open in :{tech.domain_from === "onprem" ? "ad-graph" : tech.domain_from} →
          </a>
        </div>
      )}
    </motion.section>
  );
}
