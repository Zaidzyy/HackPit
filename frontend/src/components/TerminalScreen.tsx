"use client";

import { useState } from "react";
import Link from "next/link";
import { PageShell } from "./PageShell";
import { SessionEngine } from "./SessionEngine";
import { RawTerminal } from "./RawTerminal";

/**
 * /terminal — the open-sandbox interactive surface, in two tabs.
 *
 *   named sessions — the tmux engine: named, parallel, PERSISTENT sessions with per-session
 *                    cwd, automatic interactive-prompt detection, a background lifecycle, and
 *                    recovery. This is the upgrade (ported from Decepticon's tools/bash).
 *   raw pty        — the single full-screen pty (vim/top/a raw shell), unchanged.
 *
 * Both drive the SAME open sandbox `:kali` uses: full network reach, NOT isolated, human-only.
 * The clean per-command transcript shell lives at /kali (sentinel-delimited, one record per
 * command) — the record reports are built from.
 */
type Tab = "sessions" | "pty";

export function TerminalScreen() {
  const [tab, setTab] = useState<Tab>("sessions");

  return (
    <PageShell crumbs={[{ label: "kali" }]}>
      <div className="hp-kali hp-pty">
        <header className="hp-kali-head">
          <div className="hp-ap-kicker">
            human-only · full network reach · NOT isolated · persistent tmux sessions
          </div>
          <h1 className="hp-kali-title">:terminal</h1>
          <p className="hp-kali-sub">
            Interactive tooling in a sandbox with <b>full network reach</b>.{" "}
            <b>Named persistent sessions</b> keep their own cwd/env and run interactive tools —
            an <code>msfconsole</code>, a <code>sliver-client</code>, an{" "}
            <code>evil-winrm</code> shell, any REPL — with <b>automatic prompt detection</b>: the
            engine tells you when a tool is <b>waiting for input</b> so you can drive it without
            workarounds, and long scans run in the background with a completion notice.{" "}
            <b>Input is human-only</b>, every line. Need a clean per-command transcript for a
            report? use the{" "}
            <Link href="/kali" className="hp-pty-xlink">
              transcript shell →
            </Link>
            .
          </p>
        </header>

        <div className="hp-tt-tabs" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "sessions"}
            className={`hp-tt-tab ${tab === "sessions" ? "hp-tt-tab-on" : ""}`}
            onClick={() => setTab("sessions")}
          >
            named sessions
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "pty"}
            className={`hp-tt-tab ${tab === "pty" ? "hp-tt-tab-on" : ""}`}
            onClick={() => setTab("pty")}
          >
            raw pty
          </button>
        </div>

        {tab === "sessions" ? <SessionEngine /> : <RawTerminal embedded />}
      </div>
    </PageShell>
  );
}
