"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import {
  ApiError,
  createWindowsProfile,
  deleteWindowsProfile,
  getWindowsStatus,
  listWindowsProfiles,
  testWindowsProfile,
  type WindowsProfile,
  type WindowsStatus,
  type WindowsTestResult,
} from "@/lib/api";

/**
 * Windows targets — saved WinRM connection profiles (the "Windows targets" store).
 *
 * A profile names ONE Windows/AD box HackPit can drive over WinRM. Switching which VM the
 * cockpit drives is "pick a different profile" (a different host + creds). Secrets are
 * write-only here: created/updated, never returned (only `has_secret`). Commands run on a
 * selected profile through the SAME gated executor as every other command — this screen just
 * manages the connections. See docs/WINDOWS-EXECUTION.md.
 */
export function WindowsTargetsScreen() {
  const [status, setStatus] = useState<WindowsStatus | null>(null);
  const [profiles, setProfiles] = useState<WindowsProfile[]>([]);
  const [error, setError] = useState<string | null>(null);

  // create form
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("5985");
  const [username, setUsername] = useState("");
  const [domain, setDomain] = useState("");
  const [authKind, setAuthKind] = useState<"password" | "ntlm-hash">("password");
  const [secret, setSecret] = useState("");
  const [creating, setCreating] = useState(false);

  // per-profile test result
  const [tested, setTested] = useState<Record<string, WindowsTestResult>>({});
  const [testing, setTesting] = useState<string | null>(null);

  const refresh = useCallback(() => {
    getWindowsStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
    listWindowsProfiles()
      .then(setProfiles)
      .catch(() => setProfiles([]));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const create = useCallback(async () => {
    if (!name.trim() || !host.trim() || !username.trim() || creating) return;
    setCreating(true);
    setError(null);
    try {
      await createWindowsProfile({
        name: name.trim(),
        host: host.trim(),
        username: username.trim(),
        port: port.trim() ? Number(port) : 5985,
        auth_kind: authKind,
        secret,
        domain: domain.trim(),
      });
      setName("");
      setHost("");
      setUsername("");
      setDomain("");
      setSecret("");
      setPort("5985");
      refresh();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "could not create the profile");
    } finally {
      setCreating(false);
    }
  }, [name, host, username, port, authKind, secret, domain, creating, refresh]);

  const remove = useCallback(
    async (id: string) => {
      setError(null);
      try {
        await deleteWindowsProfile(id);
        refresh();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "could not delete the profile");
      }
    },
    [refresh]
  );

  const test = useCallback(async (id: string) => {
    setTesting(id);
    setError(null);
    try {
      const res = await testWindowsProfile(id);
      setTested((prev) => ({ ...prev, [id]: res }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "connectivity test failed to run");
    } finally {
      setTesting(null);
    }
  }, []);

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "windows targets" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">WinRM driver · CRTP · OSCP AD · internal pentest</div>
          <h1 className="hp-tn-title">:windows targets</h1>
          <p className="hp-tn-sub">
            Saved connections to a Windows/AD box HackPit drives over WinRM. Pick one on the
            cockpit or AD walk to run PowerShell / Rubeus / PowerView / Mimikatz on the box —
            through the same gates (approve-each · danger red-confirm). Secrets are write-only:
            stored, never shown.
          </p>
          {status && (
            <div className="hp-tn-status">
              <span className="hp-tn-dot" />
              {status.profiles} profile{status.profiles === 1 ? "" : "s"} ·{" "}
              {status.pywinrm_installed
                ? "pywinrm installed (live runs ready)"
                : "pywinrm NOT installed — profiles save; live runs need `pip install -r backend/requirements-winrm.txt`"}
            </div>
          )}
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">add a Windows target</div>
          <div className="hp-tn-form">
            <input
              className="hp-tn-input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="name (e.g. DC01 — corp.local)"
              aria-label="Profile name"
            />
            <input
              className="hp-tn-input"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="host / IP (e.g. 10.10.10.5)"
              aria-label="Host"
            />
            <input
              className="hp-tn-port"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="5985"
              aria-label="WinRM port"
            />
            <input
              className="hp-tn-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="username (local or domain)"
              aria-label="Username"
            />
            <input
              className="hp-tn-input"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="domain (optional, e.g. corp.local)"
              aria-label="Domain"
            />
            <select
              className="hp-tn-input"
              value={authKind}
              onChange={(e) => setAuthKind(e.target.value as "password" | "ntlm-hash")}
              aria-label="Auth kind"
            >
              <option value="password">password</option>
              <option value="ntlm-hash">NTLM hash (pass-the-hash)</option>
            </select>
            <input
              className="hp-tn-input"
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={authKind === "ntlm-hash" ? "NT hash (or LM:NT)" : "password"}
              aria-label="Secret"
              autoComplete="new-password"
            />
          </div>
          {/* CONFIGURE above, ACT below — the same shared divider :exposure and :oob use. */}
          <div className="hp-tn-actions">
            <span className="hp-tn-actions-label">act</span>
            <button
              className="hp-tn-start"
              onClick={create}
              disabled={creating || !name.trim() || !host.trim() || !username.trim()}
            >
              {creating ? "saving…" : "save target"}
            </button>
          </div>
          <p className="hp-tn-note">
            A captured credential from an engagement can fill a connection — its hash/password
            stays server-side. (Tip: `secretsdump` a hash, then create the profile from it.)
          </p>
        </section>

        {profiles.length > 0 && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">saved targets</div>
            <ul className="hp-tn-list">
              {profiles.map((p) => {
                const t = tested[p.profile_id];
                return (
                  <li key={p.profile_id} className="hp-tn-row">
                    <div className="hp-tn-rowtop">
                      <span className="hp-tn-kind">{p.name}</span>
                      <span className="hp-tn-subs">
                        {p.username}
                        {p.domain ? `@${p.domain}` : ""} → {p.host}:{p.port} · {p.transport} ·{" "}
                        {p.auth_kind}
                        {p.has_secret ? " · secret set" : " · ⚠ no secret"}
                      </span>
                      <button
                        className="hp-tn-stop"
                        onClick={() => test(p.profile_id)}
                        disabled={testing === p.profile_id}
                        style={{ marginLeft: "auto" }}
                      >
                        {testing === p.profile_id ? "testing…" : "test"}
                      </button>
                      <button className="hp-tn-stop" onClick={() => remove(p.profile_id)}>
                        delete
                      </button>
                    </div>
                    {t && (
                      <div className="hp-tn-oneliner">
                        <div className="hp-tn-olhint">
                          {t.ok
                            ? `✓ reached ${t.host} — ${(t.stdout || "").trim() || "authenticated"}`
                            : `✗ ${t.host}: ${t.error || t.stderr || "connection failed"}`}
                        </div>
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          </section>
        )}

        {profiles.length === 0 && (
          <p className="hp-tn-sub">
            No Windows targets yet. Stand up a VM (see docs/WINDOWS-TARGET-SETUP.md), enable
            WinRM, then add it above.
          </p>
        )}
      </div>
    </PageShell>
  );
}
