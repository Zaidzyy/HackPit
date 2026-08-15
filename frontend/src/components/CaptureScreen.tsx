"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageShell } from "./PageShell";
import {
  ApiError,
  getBenchStatus,
  startBench,
  stopBench,
  type BenchStatus,
} from "@/lib/api";

/**
 * :capture — launch the mobile-capture BENCH on the host from cockpit. THE ONE surface that runs a
 * host command, not a sandboxed one, so it is OFF by default (HACKPIT_HOST_BENCH), HUMAN-ONLY (no
 * loop path), and it launches ONE fixed script with whitelisted args. Setup is automated; the login
 * and the capture-paste into :repeater stay human.
 */
export function CaptureScreen() {
  const [status, setStatus] = useState<BenchStatus | null>(null);
  const [apk, setApk] = useState("");
  const [pkg, setPkg] = useState("");
  const [avd, setAvd] = useState("");
  const [port, setPort] = useState("8080");
  const [frida, setFrida] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);

  const refresh = useCallback((signal?: AbortSignal) => {
    getBenchStatus(signal)
      .then(setStatus)
      .catch(() => {});
  }, []);

  const running = status?.job?.state === "running";

  useEffect(() => {
    const ctrl = new AbortController();
    refresh(ctrl.signal);
    const t = setInterval(() => refresh(), running ? 1200 : 5000);
    return () => {
      ctrl.abort();
      clearInterval(t);
    };
  }, [refresh, running]);

  const launch = useCallback(() => {
    if (launching) return;
    setLaunching(true);
    setError(null);
    startBench({
      apk: apk.trim() || undefined,
      pkg: pkg.trim() || undefined,
      avd: avd.trim() || undefined,
      port: Number.parseInt(port, 10) || 8080,
      frida,
    })
      .then(() => refresh())
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setLaunching(false));
  }, [launching, apk, pkg, avd, port, frida, refresh]);

  const stop = useCallback(() => {
    stopBench()
      .then(() => refresh())
      .catch(() => {});
  }, [refresh]);

  const job = status?.job ?? null;
  const enabled = status?.enabled ?? false;
  const ready = (job?.lines ?? []).some((l) => /BENCH READY|log in/i.test(l));

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "capture" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">host bench · human-approved · on by default</div>
          <h1 className="hp-tn-title">:capture</h1>
          <p className="hp-tn-sub">
            Launch the mobile-capture bench <strong>on the host</strong> from cockpit — boot the
            emulator, install the app, trust the proxy cert, point the device at mitmproxy — then it
            stops and asks you to <strong>log in</strong>. Grab the request in mitmweb and paste it
            into <Link href="/repeater">:repeater</Link> import. This is the one surface that runs a{" "}
            <strong>host</strong> command; it is <strong>on by default</strong>, a human approves each
            launch, and it runs only one fixed script.
          </p>
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        {!enabled ? (
          <section className="hp-tn-card">
            <p className="hp-tn-note">
              The host-bench launcher is <strong>disabled</strong>. It is <strong>on by default</strong>,
              but the backend was started with the kill-switch{" "}
              <code>{status?.enable_env ?? "HACKPIT_HOST_BENCH"}=0</code>. Remove that (or set it to{" "}
              <code>1</code>) and restart the backend to re-enable it. Everything here is otherwise inert.
            </p>
          </section>
        ) : (
          <section className="hp-tn-card">
            <div className="hp-tn-form">
              <input
                className="hp-tn-port"
                value={apk}
                onChange={(e) => setApk(e.target.value)}
                placeholder="app bundle path (.apkm/.apk) — optional"
                aria-label="APK path"
                style={{ flex: "1 1 360px" }}
              />
              <input
                className="hp-tn-port"
                value={pkg}
                onChange={(e) => setPkg(e.target.value)}
                placeholder="APP_MATCH (e.g. fishbowl)"
                aria-label="Package match"
              />
            </div>
            <div className="hp-tn-form">
              <input
                className="hp-tn-port"
                value={avd}
                onChange={(e) => setAvd(e.target.value)}
                placeholder="AVD name (blank = first)"
                aria-label="AVD name"
              />
              <input
                className="hp-tn-port"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="proxy port"
                aria-label="Proxy port"
              />
              <button
                type="button"
                className={`hp-tn-chip${frida ? " is-on" : ""}`}
                onClick={() => setFrida((v) => !v)}
                title="Also push+start frida-server (only for cert-pinned apps; note anti-tamper RASP may still block it)."
              >
                push frida-server
              </button>
            </div>
            <div className="hp-tn-form">
              <button
                type="button"
                className="hp-ck-approve"
                onClick={launch}
                disabled={launching || running}
              >
                {running ? "bench running…" : launching ? "launching…" : "launch capture bench"}
              </button>
              {running && (
                <button type="button" onClick={stop}>
                  stop
                </button>
              )}
            </div>
          </section>
        )}

        {ready && (
          <p className="hp-tn-note">
            <strong>Bench ready — log in now.</strong> Open the app in the emulator, log in as your
            test account, grab the request in mitmweb (<code>http://127.0.0.1:8081</code>), and paste
            it into <Link href="/repeater">:repeater</Link> import.
          </p>
        )}

        {job && (
          <section className="hp-tn-card">
            <div className={`hp-tn-status ${running ? "is-up" : "is-down"}`}>
              <span className="hp-tn-dot" />
              bench {job.state}
              {job.exit_code !== null ? ` · exit ${job.exit_code}` : ""}
            </div>
            <pre
              style={{
                marginTop: "0.6rem",
                maxHeight: "48vh",
                overflow: "auto",
                fontFamily: "monospace",
                fontSize: "12px",
                whiteSpace: "pre-wrap",
                background: "var(--panel, rgba(0,0,0,0.25))",
                padding: "0.6rem",
                borderRadius: "6px",
              }}
            >
              {(job.lines ?? []).join("\n") || "(waiting for output…)"}
            </pre>
          </section>
        )}
      </div>
    </PageShell>
  );
}
