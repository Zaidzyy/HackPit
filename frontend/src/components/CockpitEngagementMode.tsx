"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  enterEngagement,
  execCockpitStream,
  exitEngagement,
  getEngagementStatus,
  type EngagementRecord,
  type EngagementStatus,
  type ExecEvent,
} from "@/lib/api";
import { CockpitLoop } from "./CockpitLoop";

/**
 * REAL-TARGET engagement mode — the SUPERVISED, highest-risk surface.
 *
 * The engagement sandbox is FULLY OPEN (Wall A down): it reaches the internet, your LAN, AND
 * your own machine — nothing bounds where it can reach. The guided loop may DRAFT commands, but
 * every command still needs the operator's explicit approval — the loop never fires on its own,
 * and there is no batch, no approve-all. Human approval of EVERY command is the ONLY guard.
 * You enter engagement mode explicitly (naming the real target, the authorized PROGRAM SCOPE,
 * and acknowledging you are authorized), then approve each command (drafted by the loop or
 * typed yourself) one at a time.
 *
 * The scope is what the loop is told it may target and what the argv target-lock checks — but
 * with the sandbox fully open, that lock is best-effort defence in depth, not a network bound.
 * The panel below is deliberately honest about that.
 */

type Line = { kind: "stdout" | "stderr" | "meta" | "err" | "disc"; text: string };

export function CockpitEngagementMode({
  sessionId = null,
  onRunRecorded,
}: {
  sessionId?: string | null;
  onRunRecorded?: () => void;
}) {
  const [status, setStatus] = useState<EngagementStatus | null>(null);
  const [active, setActive] = useState<EngagementRecord | null>(null);

  // enter form
  const [target, setTarget] = useState("");
  const [scopeSpec, setScopeSpec] = useState("");
  const [auth, setAuth] = useState("");
  const [entering, setEntering] = useState(false);
  const [enterErr, setEnterErr] = useState<string | null>(null);

  // loop (drafts, human approves each) vs manual approve-each. Defaults to the guided loop for
  // symmetry with lab mode; never-auto-run still gates every run (the loop drafts, you approve).
  const [engExecMode, setEngExecMode] = useState<"loop" | "manual">("loop");

  // command surface
  const [command, setCommand] = useState("nmap");
  const [argsText, setArgsText] = useState("");
  const [dangerAck, setDangerAck] = useState(false);
  // Kept as TEXT, not a number: "" has to stay distinguishable from 0, and only a blank
  // field may mean "unpaced". Parsed once, at send time.
  const [paceText, setPaceText] = useState("");
  const [running, setRunning] = useState(false);
  const [exitCode, setExitCode] = useState<number | null>(null);
  const [lines, setLines] = useState<Line[]>([]);

  const ctrlRef = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);

  const refresh = useCallback((signal?: AbortSignal) => {
    getEngagementStatus(signal)
      .then((s) => {
        setStatus(s);
        setActive(s.active[0] ?? null);
      })
      .catch(() => setStatus(null));
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    refresh(ctrl.signal);
    return () => ctrl.abort();
  }, [refresh]);
  useEffect(() => () => ctrlRef.current?.abort(), []);
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [lines]);

  const args = useMemo(
    () => argsText.trim().split(/\s+/).filter(Boolean),
    [argsText]
  );
  const preview = `${command} ${args.join(" ")}`.trim();
  const ready = status?.ready ?? false;

  const doEnter = useCallback(() => {
    const t = target.trim();
    const a = auth.trim();
    if (!t || !a || entering) return;
    setEntering(true);
    setEnterErr(null);
    enterEngagement(t, a, sessionId, undefined, scopeSpec)
      .then((rec) => {
        setActive(rec);
        setArgsText(rec.target); // seed the first command with the target
        refresh();
      })
      .catch((err: unknown) =>
        setEnterErr(err instanceof ApiError ? err.message : "Couldn’t enter engagement mode.")
      )
      .finally(() => setEntering(false));
  }, [target, auth, scopeSpec, entering, sessionId, refresh]);

  const doExit = useCallback(() => {
    if (!active) return;
    exitEngagement(active.engagement_id)
      .catch(() => {})
      .finally(() => {
        setActive(null);
        setLines([]);
        setExitCode(null);
        refresh();
      });
  }, [active, refresh]);

  const approveAndRun = useCallback(() => {
    if (!active || running || args.length === 0) return;
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    setRunning(true);
    setExitCode(null);
    setLines([{ kind: "meta", text: `$ ${preview}` }]);
    const push = (l: Line) => setLines((prev) => [...prev, l]);

    execCockpitStream(
      {
        command,
        args,
        approved: true,
        dangerous_ack: dangerAck,
        engagement_id: active.engagement_id,
        session_id: sessionId,
        // Number.isFinite, not a truthiness check: a blank field must send null rather
        // than NaN, and the server treats null as "not asked for".
        pace: Number.isFinite(Number(paceText)) && paceText.trim() !== ""
          ? Number(paceText)
          : null,
      },
      (ev: ExecEvent) => {
        switch (ev.type) {
          case "start":
            push({ kind: "meta", text: `▶ run ${ev.run_id} → ${ev.target} [${ev.mode ?? "?"}]` });
            // How the run was rewritten — INCLUDING "this went at full speed". Printed
            // before any output, because that is the only point at which it can still
            // change what the operator does.
            for (const n of ev.notes ?? []) push({ kind: "meta", text: `· ${n}` });
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
          case "discovered":
            // Recon-driven expansion: in-scope hosts joined the allowed set; out-of-scope
            // ones are shown but never targetable. Neither approves anything.
            if (ev.in_scope.length)
              push({ kind: "disc", text: `+ in scope: ${ev.in_scope.join(", ")}` });
            if (ev.out_of_scope.length)
              push({
                kind: "disc",
                text: `· seen, OUT of scope (not added): ${ev.out_of_scope.join(", ")}`,
              });
            if (ev.truncated) push({ kind: "disc", text: "· …more discoveries were capped" });
            break;
          case "error":
            push({ kind: "err", text: `✕ ${ev.reason}` });
            break;
          case "exit":
            setExitCode(ev.code);
            push({ kind: "meta", text: `■ exit ${ev.code}` });
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
        setRunning(false);
        setDangerAck(false); // re-confirm consciously for the next command
        onRunRecorded?.();
        refresh(); // pick up any hosts this run added to the live allowed set
      });
    // paceText belongs here for the same reason dangerAck does: the callback READS it, so
    // omitting it memoizes a stale closure and the run would be paced at whatever the field
    // held when this was last rebuilt — a silently wrong rate, which is the one outcome the
    // whole feature exists to prevent.
  }, [
    active, running, args, command, preview, dangerAck, paceText, sessionId,
    onRunRecorded, refresh,
  ]);

  // ---- NOT ENTERED: the deliberate, warned entry ---------------------------- //
  if (!active) {
    return (
      <div className="hp-eng">
        <div className="hp-eng-warn" role="alert">
          <p className="hp-eng-warn-head">⚠ You are about to leave the isolated lab.</p>
          <p>
            Engagement mode runs against a <b>real target</b> with <b>no isolation floor and no
            Wall A</b>. The sandbox is <b>FULLY OPEN</b> — it reaches the internet, <b>your LAN,
            and your own machine</b>; nothing bounds where it can reach. You are responsible for
            authorization and for staying in scope. The guided loop may <b>draft</b> commands, but
            <b> human approval of every command is the only guard</b> — the loop never fires on its
            own, and there is no autonomous mode, no batch, no approve-all.
          </p>
        </div>

        <div className="hp-eng-enter">
          <label className="hp-ck-field">
            <span>real target (host or URL you are authorized to test)</span>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. scanme.nmap.org"
              spellCheck={false}
              autoComplete="off"
              disabled={entering}
            />
          </label>
          <label className="hp-ck-field">
            <span>
              authorized scope (optional — defaults to just the target)
            </span>
            <input
              type="text"
              value={scopeSpec}
              onChange={(e) => setScopeSpec(e.target.value)}
              placeholder="e.g. *  ·  or: example.com, *.example.com, 10.10.10.0/24, !admin.example.com"
              spellCheck={false}
              autoComplete="off"
              disabled={entering}
            />
          </label>
          <p className="hp-ck-hint">
            <code>*</code> means <b>everything is authorized</b> — the target check passes any
            host you name. Otherwise: exact hosts, <code>*.wildcards</code> and CIDRs, separated
            by commas; prefix a pattern with <code>!</code> to exclude it (exclusions win, even
            over <code>*</code>). A wildcard covers subdomains <b>and</b> the apex. The loop may
            target anything in scope, and in-scope hosts that recon discovers are added
            automatically; you still approve every command.
          </p>
          <label className="hp-ck-field">
            <span>authorization acknowledgement (required)</span>
            <input
              type="text"
              value={auth}
              onChange={(e) => setAuth(e.target.value)}
              placeholder="I am authorized to test this target and will stay in scope."
              spellCheck={false}
              autoComplete="off"
              disabled={entering}
            />
          </label>
          <button
            type="button"
            className="hp-ck-approve is-danger"
            onClick={doEnter}
            disabled={entering || !target.trim() || !auth.trim()}
            title="Deliberately enter real-target engagement mode"
          >
            {entering ? "entering…" : "ENTER ENGAGEMENT MODE →"}
          </button>
          {enterErr && <p className="hp-cv-error">{enterErr}</p>}
        </div>

        <div
          className={`hp-ck-banner ${ready ? "hp-ck-warn" : "hp-ck-warn"}`}
          role="status"
        >
          {status ? (
            ready ? (
              <>
                <span className="hp-ck-dot" /> engagement sandbox <b>{status.sandbox}</b> ready ·
                <b> FULLY OPEN</b> · full network reach (internet + LAN + host) · human-approve-each
              </>
            ) : (
              <>
                <span className="hp-ck-dot" /> engagement sandbox not running —{" "}
                {status.detail || "bring it up"}.{" "}
                <code>docker compose -f docker/docker-compose.yml up -d --build</code>
              </>
            )
          ) : (
            <>connecting to backend…</>
          )}
        </div>
      </div>
    );
  }

  // ---- ENTERED: always-shown mode indicator + manual approve-each ----------- //
  return (
    <div className="hp-eng hp-eng-live">
      <div className="hp-eng-mode" role="status">
        <span className="hp-eng-mode-tag">ENGAGEMENT · REAL TARGET</span>
        <span className="hp-eng-mode-target">
          target <b>{active.target}</b>
        </span>
        <span className="hp-eng-wall-bad">
          {ready ? "FULLY OPEN · full reach" : "sandbox not running"}
        </span>
        <button type="button" className="hp-loop-stop" onClick={doExit}>
          exit engagement
        </button>
      </div>

      {/* The authorized scope + the LIVE allowed set (seed hosts + in-scope recon finds). */}
      <section className="hp-eng-scope" aria-label="Authorized scope">
        <div className="hp-eng-scope-row">
          <span className="hp-eng-scope-key">in scope</span>
          <span className="hp-eng-scope-vals">
            {(active.scope_include.length ? active.scope_include : [active.target]).map((p) => (
              <code key={p} className="hp-eng-chip">
                {p}
              </code>
            ))}
          </span>
        </div>
        {active.scope_exclude.length > 0 && (
          <div className="hp-eng-scope-row">
            <span className="hp-eng-scope-key">excluded</span>
            <span className="hp-eng-scope-vals">
              {active.scope_exclude.map((p) => (
                <code key={p} className="hp-eng-chip is-out">
                  !{p}
                </code>
              ))}
            </span>
          </div>
        )}
        <div className="hp-eng-scope-row">
          <span className="hp-eng-scope-key">
            allowed hosts{" "}
            <span className="hp-eng-scope-count">({active.allowed_hosts.length})</span>
          </span>
          <span className="hp-eng-scope-vals">
            {active.allowed_hosts.map((h) => (
              <code
                key={h}
                className={`hp-eng-chip${
                  active.discovered_in_scope.includes(h) ? " is-new" : ""
                }`}
                title={
                  active.discovered_in_scope.includes(h)
                    ? "discovered by recon — in scope, so added automatically"
                    : "from the scope you entered"
                }
              >
                {h}
              </code>
            ))}
          </span>
        </div>
        {active.discovered_out_of_scope.length > 0 && (
          <div className="hp-eng-scope-row">
            <span className="hp-eng-scope-key">
              seen, out of scope{" "}
              <span className="hp-eng-scope-count">
                ({active.discovered_out_of_scope.length})
              </span>
            </span>
            <span className="hp-eng-scope-vals">
              {active.discovered_out_of_scope.map((h) => (
                <code
                  key={h}
                  className="hp-eng-chip is-out"
                  title="revealed by recon but NOT in your scope — never added, never targeted"
                >
                  {h}
                </code>
              ))}
            </span>
          </div>
        )}
      </section>

      <p className="hp-ck-note">
        No isolation floor, no Wall A — the sandbox reaches the internet, your LAN, and your own
        machine. The scope above is what the agent is told it may target and what the argument
        check enforces, but <b>nothing stops an off-scope packet at the network layer</b> — that
        check is best-effort defence in depth, not a wall. The guided loop may <b>draft</b>
        commands, but <b>you approve every command</b> before it runs — including commands
        against hosts recon discovered. The loop never fires on its own; there is no batch or
        approve-all. Human approval of every command is the <b>only</b> guard.
      </p>

      <div className="hp-cv-execmode" role="tablist" aria-label="Execution mode">
        <button
          type="button"
          role="tab"
          aria-selected={engExecMode === "loop"}
          className={engExecMode === "loop" ? "is-on" : undefined}
          onClick={() => setEngExecMode("loop")}
          disabled={!sessionId}
          title={sessionId ? "Agent drafts each step; you approve every command" : "Needs a saved engagement to record against"}
        >
          guided loop
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={engExecMode === "manual"}
          className={engExecMode === "manual" ? "is-on" : undefined}
          onClick={() => setEngExecMode("manual")}
        >
          manual
        </button>
      </div>

      {engExecMode === "loop" ? (
        /* The loop DRAFTS proposals; each approved run routes through _validate_engagement
           (target -> approval -> danger) with this engagement's id. It never fires without
           your click. Needs a saved engagement (sessionId) to propose against — mirrors lab. */
        sessionId ? (
          <CockpitLoop
            sessionId={sessionId}
            engagementId={active.engagement_id}
            scopeLabel={active.scope || active.target}
            onRunRecorded={() => {
              onRunRecorded?.();
              refresh(); // a loop run may have expanded the live allowed set
            }}
          />
        ) : (
          <p className="hp-cv-hint">
            The guided loop needs a saved engagement to propose against — it wasn&apos;t
            created. Re-plot the path, or switch to <b>manual</b> to run commands yourself.
          </p>
        )
      ) : (
      <>
      <section className="hp-ck-builder">
        <label className="hp-ck-field">
          <span>command</span>
          <input
            type="text"
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            spellCheck={false}
            disabled={running}
          />
        </label>
        <label className="hp-ck-field hp-ck-args">
          <span>
            arguments (must reference a host in scope
            {active.scope && active.scope !== active.target ? `: ${active.scope}` : ` — ${active.target}`})
          </span>
          <input
            type="text"
            value={argsText}
            onChange={(e) => setArgsText(e.target.value)}
            spellCheck={false}
            disabled={running}
          />
        </label>

        {/* PACING (D3) — engagement mode only, which is why the control lives here and
            nowhere else. Nothing throttled anything before this; a default-off blank means
            the run goes at full speed, exactly as it always has. Whether it actually applied
            is reported per-run in the output, because this tool's flag map cannot cover
            every tool and a pace the operator believes in but did not get is the failure
            mode worth designing against. */}
        <label className="hp-ck-field hp-eng-pace">
          <span>
            pace — max requests/second (blank = full speed). Adds the tool&rsquo;s own rate or
            delay flag; the run says whether it took.
          </span>
          <input
            type="number"
            min={1}
            max={10000}
            placeholder="e.g. 5"
            value={paceText}
            onChange={(e) => setPaceText(e.target.value)}
            disabled={running}
          />
        </label>

        <label className="hp-eng-ack">
          <input
            type="checkbox"
            checked={dangerAck}
            onChange={(e) => setDangerAck(e.target.checked)}
          />
          <span>
            Confirm dangerous commands (interpreters, shells, frameworks) for this run — needed
            only if the server flags it.
          </span>
        </label>

        <div className="hp-ck-run">
          <code className="hp-ck-preview">{preview}</code>
          <button
            type="button"
            className="hp-ck-approve is-danger"
            onClick={approveAndRun}
            disabled={running || !ready || args.length === 0}
            title={ready ? "Approve and run against the real target" : "Engagement sandbox not running"}
          >
            {running ? "running…" : "APPROVE & RUN (REAL TARGET)"}
          </button>
        </div>
      </section>

      <section className="hp-ck-out-wrap">
        <div className="hp-ck-out-bar">
          <span className="hp-ck-out-lights" aria-hidden>
            <i />
            <i />
            <i />
          </span>
          <span className="hp-ck-out-title">
            {running ? "engagement · streaming" : "engagement · terminal"}
          </span>
          {exitCode !== null && (
            <span className={exitCode === 0 ? "hp-ck-exit0" : "hp-ck-exitn"}>
              exit {exitCode}
            </span>
          )}
        </div>
        <div className="hp-ck-out" ref={outRef}>
          {lines.length === 0 ? (
            <span className="hp-ck-empty">approve a command to see live output…</span>
          ) : (
            <>
              {lines.map((l, i) => (
                <div key={i} className={`hp-ck-line hp-ck-${l.kind}`}>
                  {l.text || " "}
                </div>
              ))}
              {running && (
                <div className="hp-ck-line hp-ck-cursor" aria-hidden>
                  ▋
                </div>
              )}
            </>
          )}
        </div>
      </section>
      </>
      )}
    </div>
  );
}
