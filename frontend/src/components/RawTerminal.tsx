"use client";

import "@xterm/xterm/css/xterm.css";
import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { PageShell } from "./PageShell";
import { getTerminalStatus, terminalSocketUrl, type TerminalStatus } from "@/lib/api";

/**
 * :terminal — a raw PTY terminal into the SAME open sandbox `:kali` uses.
 *
 * This is a SECOND surface, not a replacement. `/kali` keeps its sentinel-delimited
 * shell: clean, escape-free, per-command transcripts, which is what reports are built
 * from. That design cannot render full-screen tools, so this page exists for the other
 * half — vim, top, an interactive msfconsole, a raw evil-winrm shell, a `pty.spawn`
 * upgrade. Raw bytes go both directions over a WebSocket; the container is hardcoded
 * server-side (this UI sends no target, no shell, no command — only a window size).
 *
 * The containment is identical to :kali's: full network reach, NOT isolated, human-only,
 * and every session's raw stream is recorded to the engagement run store.
 *
 * xterm.js is loaded dynamically inside the effect: it touches `window`/`document` at
 * construction time, so it must never be pulled in during SSR.
 */

type Phase = "idle" | "connecting" | "live" | "closed" | "refused";

export function RawTerminal() {
  const hostRef = useRef<HTMLDivElement | null>(null);
  // Kept in refs, not state: these are imperative handles the effect owns, and touching
  // state for them would tear down the terminal on every render.
  const termRef = useRef<{ dispose: () => void; write: (d: Uint8Array) => void } | null>(null);
  const fitRef = useRef<{ fit: () => void } | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const [status, setStatus] = useState<TerminalStatus | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [detail, setDetail] = useState<string>("");
  const [size, setSize] = useState<{ cols: number; rows: number } | null>(null);
  // The effect that owns the terminal keys on THIS, never on `phase`. `phase` is what the
  // effect's own handlers write, so keying on it would tear the terminal down the instant
  // it went live. 0 = nothing attached; each attach/restart bumps it.
  const [attachKey, setAttachKey] = useState(0);

  // --- availability banner ---------------------------------------------------
  useEffect(() => {
    const ctrl = new AbortController();
    getTerminalStatus(ctrl.signal)
      .then((s) => setStatus(s))
      .catch(() => setStatus(null));
    return () => ctrl.abort();
  }, [attachKey]);

  // --- the terminal itself ---------------------------------------------------
  useEffect(() => {
    if (attachKey === 0) return;
    const host = hostRef.current;
    if (!host) return;

    let disposed = false;
    let cleanup = () => {};

    (async () => {
      const [{ Terminal }, { FitAddon }] = await Promise.all([
        import("@xterm/xterm"),
        import("@xterm/addon-fit"),
      ]);
      if (disposed) return;

      const term = new Terminal({
        convertEol: false, // the pty already speaks CRLF — do not "help"
        cursorBlink: true,
        fontFamily:
          'var(--font-mono, ui-monospace), "JetBrains Mono", "SF Mono", Menlo, monospace',
        fontSize: 13,
        lineHeight: 1.2,
        scrollback: 10000,
        allowProposedApi: true,
        theme: {
          background: "#07090c",
          foreground: "#d7e0e8",
          cursor: "#7fd1ff",
          selectionBackground: "rgba(127, 209, 255, 0.28)",
        },
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(host);
      fit.fit();

      termRef.current = {
        dispose: () => term.dispose(),
        write: (d) => term.write(d),
      };
      fitRef.current = fit;
      setSize({ cols: term.cols, rows: term.rows });

      // Open the socket with the CURRENT geometry, so the very first `top` renders at the
      // real size instead of the 80x24 default.
      const ws = new WebSocket(terminalSocketUrl(term.cols, term.rows));
      ws.binaryType = "arraybuffer";
      wsRef.current = ws;

      // Every handler below is guarded on `disposed`. React StrictMode mounts effects
      // twice in dev (mount -> cleanup -> mount), so a DISCARDED socket's onclose would
      // otherwise fire after the replacement is live and mark the live terminal closed.
      ws.onmessage = (ev) => {
        if (disposed) return;
        if (typeof ev.data === "string") {
          // Control messages: ready / refused. Everything else is raw pty bytes.
          try {
            const msg = JSON.parse(ev.data) as { type?: string; reason?: string };
            if (msg.type === "ready") {
              setPhase("live");
            } else if (msg.type === "refused") {
              setPhase("refused");
              setDetail(msg.reason ?? "the backend refused the terminal");
            }
          } catch {
            /* not JSON — ignore */
          }
          return;
        }
        term.write(new Uint8Array(ev.data as ArrayBuffer));
      };
      ws.onerror = () => {
        if (disposed) return;
        setDetail("the terminal socket errored — is the backend running?");
      };
      ws.onclose = () => {
        if (disposed) return;
        setPhase((p) => (p === "refused" ? p : "closed"));
        term.write("\r\n\x1b[2m[terminal closed]\x1b[0m\r\n");
      };

      // Keystrokes go out as raw bytes. `onData` gives the exact string the terminal
      // produced — including control characters and escape sequences (Ctrl-C, arrows) —
      // which is precisely what the pty expects.
      const enc = new TextEncoder();
      term.onData((data) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(enc.encode(data));
      });
      // Pasted / bracketed-paste chunks arrive through onData too, so nothing extra here.

      const onResize = () => {
        try {
          fit.fit();
        } catch {
          /* the host may be mid-layout */
        }
        setSize({ cols: term.cols, rows: term.rows });
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
        }
      };
      const ro = new ResizeObserver(onResize);
      ro.observe(host);
      window.addEventListener("resize", onResize);

      cleanup = () => {
        ro.disconnect();
        window.removeEventListener("resize", onResize);
        try {
          ws.close();
        } catch {
          /* already gone */
        }
        term.dispose();
        termRef.current = null;
        fitRef.current = null;
        wsRef.current = null;
      };
    })();

    return () => {
      disposed = true;
      cleanup();
    };
  }, [attachKey]);

  const start = useCallback(() => {
    setDetail("");
    setPhase("connecting");
    setAttachKey((n) => n + 1);
  }, []);

  const restart = useCallback(() => {
    setDetail("");
    setPhase("connecting");
    setAttachKey((n) => n + 1); // the effect's cleanup closes the previous socket + pty
  }, []);

  const ready = !!status?.ready;

  return (
    <PageShell crumbs={[{ label: "terminal" }]}>
      <div className="hp-kali hp-pty">
        <header className="hp-kali-head">
          <div className="hp-ap-kicker">
            human-only · full network reach · NOT isolated · real PTY
          </div>
          <h1 className="hp-kali-title">:terminal</h1>
          <p className="hp-kali-sub">
            A <b>real terminal</b> in the same sandbox <code>:kali</code> uses — a true
            PTY, so full-screen tools work: <code>vim</code>, <code>top</code>, an
            interactive <code>msfconsole</code>, a raw <code>evil-winrm</code> shell, a{" "}
            <code>pty.spawn</code> upgrade. Same box, same reach: the internet, this host
            and your LAN, with <b>no isolation</b>.{" "}
            <Link href="/kali" className="hp-pty-xlink">
              :kali
            </Link>{" "}
            is unchanged and still the right surface for one-shot commands — it keeps the
            clean per-command transcripts that reports are built from. This one streams
            raw bytes, and its whole session is recorded as one transcript.
          </p>
        </header>

        {/* readiness banner — availability only; makes NO isolation claim (there is none) */}
        <div
          className={`hp-ck-banner ${ready ? "hp-kali-warnbanner" : "hp-ck-warn"}`}
          role="status"
        >
          {status ? (
            ready ? (
              <>
                <span className="hp-kali-dot" /> pty <b>{status.container}</b> ·{" "}
                <code>{status.shell}</code> · full network reach · <b>NOT isolated</b> ·
                human-only · {status.live}/{status.max_live} live
              </>
            ) : (
              <>
                <span className="hp-ck-dot" /> not ready —{" "}
                {status.detail || "open sandbox unavailable"}. Bring the stack up:{" "}
                <code>docker compose -f docker/docker-compose.yml up -d</code>
              </>
            )
          ) : (
            <>connecting to backend…</>
          )}
        </div>

        <section className="hp-ck-out-wrap">
          <div className="hp-ck-out-bar">
            <span className="hp-ck-out-lights" aria-hidden>
              <i />
              <i />
              <i />
            </span>
            <span className="hp-ck-out-title">
              {phase === "live"
                ? "sandbox · pty attached"
                : phase === "connecting"
                  ? "sandbox · attaching…"
                  : "sandbox · raw terminal"}
            </span>
            {size && (
              <span className="hp-pty-size" title="Live pty geometry (ioctl TIOCSWINSZ)">
                {size.cols}×{size.rows}
              </span>
            )}
            {(phase === "live" || phase === "closed") && (
              <button type="button" className="hp-kali-clear" onClick={restart}>
                {phase === "closed" ? "new terminal" : "restart"}
              </button>
            )}
          </div>

          <div className="hp-pty-stage">
            <div ref={hostRef} className="hp-pty-host" />
            {phase !== "live" && (
              <div className="hp-pty-overlay">
                {phase === "idle" && (
                  <button
                    type="button"
                    className="hp-pty-attach"
                    onClick={start}
                    disabled={!ready}
                  >
                    {ready ? "attach a terminal" : "sandbox not running"}
                  </button>
                )}
                {phase === "connecting" && <span className="hp-pty-msg">attaching…</span>}
                {phase === "closed" && (
                  <span className="hp-pty-msg">
                    terminal closed — the transcript is in the run store
                  </span>
                )}
                {phase === "refused" && <span className="hp-pty-msg">{detail}</span>}
              </div>
            )}
          </div>
        </section>

        {detail && phase === "live" && <p className="hp-pty-detail">{detail}</p>}
      </div>
    </PageShell>
  );
}
