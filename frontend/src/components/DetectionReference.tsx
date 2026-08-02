"use client";

import { useMemo, useState } from "react";
import { PageShell } from "./PageShell";
import {
  detectionCatalog,
  detectionSources,
  detectionTag,
  detectionTechnique,
  type DetectionSpec,
  type DetectionTag,
  type DetectionTechniqueDetail,
  type Loudness,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";

const DETECTION_COLOR = "#8ab4ff";

const LOUD_ORDER: Loudness[] = ["quiet", "moderate", "notable", "loud"];

/**
 * :detection — the whole curated map, browsable.
 *
 * The per-command drawer (DetectionPanel) answers "what does blue see if I run THIS".
 * This answers the other three questions the same knowledge base can serve and that had
 * no surface at all: what is in the map, what does one ATT&CK technique mean here, and
 * what is the cheap deterministic tag for an arbitrary command line.
 *
 * READ-ONLY, like every detection surface. Nothing here executes, approves, or changes a
 * gate — it describes. The blue copy is guarded server-side against drifting into evasion
 * advice; the opt-in OPSEC note carries its mandatory "still recorded" line (D10/D16).
 */
export function DetectionReference() {
  const catalog = useApi(detectionCatalog, []);
  const sources = useApi(detectionSources, []);

  const [q, setQ] = useState("");
  const [loud, setLoud] = useState<Loudness | "all">("all");

  // The deterministic tag probe — type any command line, get the catalog's reading.
  const [probe, setProbe] = useState("");
  const [probed, setProbed] = useState<{ argv: string; tag: DetectionTag | null } | null>(null);
  const [probeBusy, setProbeBusy] = useState(false);

  // One technique, expanded.
  const [tech, setTech] = useState<DetectionTechniqueDetail | null>(null);
  const [techBusy, setTechBusy] = useState("");

  const needle = q.trim().toLowerCase();
  const specs = useMemo<DetectionSpec[]>(() => {
    const all = catalog.data?.specs ?? [];
    return all.filter((s) => {
      if (loud !== "all" && s.loudness !== loud) return false;
      if (!needle) return true;
      return [s.key, s.label, s.blue_view, ...s.techniques, ...s.telemetry]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [catalog.data, loud, needle]);

  // Every setState below runs from an event handler or a promise callback, never an
  // effect body — the repo's accepted react-hooks lint baseline stays where it is.
  const runProbe = async () => {
    const argv = probe.trim();
    if (!argv) return;
    setProbeBusy(true);
    try {
      setProbed(await detectionTag({ argv }));
    } catch {
      setProbed(null);
    } finally {
      setProbeBusy(false);
    }
  };

  const openTechnique = async (id: string) => {
    if (tech?.id === id) {
      setTech(null);
      return;
    }
    setTechBusy(id);
    try {
      setTech(await detectionTechnique(id));
    } catch {
      setTech(null);
    } finally {
      setTechBusy("");
    }
  };

  const src = sources.data;

  return (
    <PageShell crumbs={[{ label: "home", href: "/" }, { label: "Detection map" }]}>
      <div className="hp-dr">
        <header className="hp-listing-head">
          <span className="hp-listing-ic" style={{ ["--cc" as string]: DETECTION_COLOR }}>
            {"◉"}
          </span>
          <div>
            <h1 className="hp-listing-title">Detection map</h1>
            <p className="hp-listing-sub">
              {src
                ? `${src.specs} command families · ${src.techniques} ATT&CK techniques · ${src.sigma_rules} Sigma rules · ${src.arg_signals} argument signals`
                : " "}
            </p>
          </div>
        </header>

        {src && (
          <p className="hp-dr-line">
            <b>This describes detection, it does not perform evasion.</b> {src.the_line}
          </p>
        )}

        {/* ---- the deterministic tag probe (POST /detection/tag) ---- */}
        <section className="hp-dr-probe">
          <h2 className="hp-dr-h">tag a command</h2>
          <p className="hp-dr-sub">
            The compact ATT&amp;CK reading, straight from the curated map — deterministic, no
            model involved. <code>tag: null</code> means the map does not cover it, which is
            not the same as untraceable.
          </p>
          <form
            className="hp-dr-probeform"
            onSubmit={(e) => {
              e.preventDefault();
              void runProbe();
            }}
          >
            <input
              className="hp-dr-input"
              value={probe}
              onChange={(e) => setProbe(e.target.value)}
              placeholder="nmap -sS -p- 10.10.11.42 · impacket-secretsdump -just-dc …"
              spellCheck={false}
              aria-label="Command line to tag"
            />
            <button type="submit" className="hp-dr-go" disabled={probeBusy || !probe.trim()}>
              {probeBusy ? "tagging…" : "tag"}
            </button>
          </form>

          {probed && (
            <div className="hp-dr-probeout">
              <code className="hp-dr-argv">{probed.argv}</code>
              {probed.tag ? (
                <div className="hp-dr-tag">
                  <span className={`hp-det-dot is-${probed.tag.loudness}`} aria-hidden />
                  <span className="hp-dr-activity">{probed.tag.activity}</span>
                  {probed.tag.techniques.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      className="hp-dr-tid"
                      onClick={() => void openTechnique(t.id)}
                    >
                      {t.id}
                    </button>
                  ))}
                  <span className="hp-dr-loud">{probed.tag.loudness}</span>
                  {probed.tag.stealth && <span className="hp-dr-stealth">stealth</span>}
                </div>
              ) : (
                <p className="hp-dr-unmapped">
                  Not in the curated map. Ask the per-command drawer for a model reading —
                  unmapped is not untraceable.
                </p>
              )}
            </div>
          )}
        </section>

        {/* ---- one technique, expanded (GET /detection/technique/{id}) ---- */}
        {tech && (
          <section className="hp-dr-tech">
            <div className="hp-dr-techhead">
              <a href={tech.url} target="_blank" rel="noreferrer noopener" className="hp-dr-tid">
                {tech.id} ↗
              </a>
              <b>{tech.name}</b>
              <button type="button" className="hp-dr-close" onClick={() => setTech(null)}>
                close
              </button>
            </div>
            {(tech.tactics ?? []).length > 0 && (
              <p className="hp-dr-techmeta">
                tactic: {(tech.tactics ?? []).map((t) => t.name).join(", ")}
              </p>
            )}
            {(tech.data_components ?? []).length > 0 && (
              <p className="hp-dr-techmeta">
                data components: {(tech.data_components ?? []).join(" · ")}
              </p>
            )}
            {(tech.log_sources ?? []).length > 0 && (
              <p className="hp-dr-techmeta">
                log channels: {(tech.log_sources ?? []).join(" · ")}
              </p>
            )}
            {(tech.sigma ?? []).length > 0 && (
              <ul className="hp-dr-sigma">
                {(tech.sigma ?? []).map((r) => (
                  <li key={r.id}>
                    <a href={r.url} target="_blank" rel="noreferrer noopener">
                      {r.title}
                    </a>
                    <span className="hp-dr-level">{r.level}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {/* ---- the catalog (GET /detection/catalog) ---- */}
        <div className="hp-dr-controls">
          <input
            type="search"
            className="hp-dr-input"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter the map — kerberos, 4662, secretsdump, share access…"
            spellCheck={false}
          />
          <div className="hp-dr-louds">
            <button
              type="button"
              className={`hp-dr-loudbtn${loud === "all" ? " hp-on" : ""}`}
              onClick={() => setLoud("all")}
            >
              all
            </button>
            {LOUD_ORDER.map((l) => (
              <button
                key={l}
                type="button"
                className={`hp-dr-loudbtn is-${l}${loud === l ? " hp-on" : ""}`}
                onClick={() => setLoud(loud === l ? "all" : l)}
              >
                {l}
              </button>
            ))}
          </div>
        </div>

        {catalog.loading && <p className="hp-dr-empty">Loading the map…</p>}
        {catalog.error && (
          <p className="hp-dr-empty">Could not load the map. Is the backend running?</p>
        )}
        {!catalog.loading && !catalog.error && specs.length === 0 && (
          <p className="hp-dr-empty">Nothing in the map matches that filter.</p>
        )}

        {specs.map((s) => (
          <article key={s.key} className={`hp-dr-spec is-${s.loudness}`}>
            <div className="hp-dr-spechead">
              <span className={`hp-det-dot is-${s.loudness}`} aria-hidden />
              <h3>{s.label}</h3>
              <span className="hp-dr-loud">{s.loudness}</span>
              {s.techniques.map((id) => (
                <button
                  key={id}
                  type="button"
                  className="hp-dr-tid"
                  disabled={techBusy === id}
                  onClick={() => void openTechnique(id)}
                >
                  {techBusy === id ? "…" : id}
                </button>
              ))}
            </div>

            <p className="hp-dr-blue">{s.blue_view}</p>
            {s.why_rating && <p className="hp-dr-why">{s.why_rating}</p>}

            {s.telemetry.length > 0 && (
              <ul className="hp-dr-telemetry">
                {s.telemetry.map((t, i) => (
                  <li key={i}>{t}</li>
                ))}
              </ul>
            )}

            {s.sigma.length > 0 && (
              <ul className="hp-dr-sigma">
                {s.sigma.map((r) => (
                  <li key={r.id}>
                    <a href={r.url} target="_blank" rel="noreferrer noopener">
                      {r.title}
                    </a>
                    <span className="hp-dr-level">{r.level}</span>
                  </li>
                ))}
              </ul>
            )}

            {/* The offensive half is opt-in per family and always carries what still logs it. */}
            {s.opsec && (
              <details className="hp-dr-opsec">
                <summary>red-team OPSEC view</summary>
                {s.opsec.loud_because && (
                  <p>
                    <strong>Loud because:</strong> {s.opsec.loud_because}
                  </p>
                )}
                {s.opsec.quieter.length > 0 && (
                  <ul>
                    {s.opsec.quieter.map((x, i) => (
                      <li key={i}>{x}</li>
                    ))}
                  </ul>
                )}
                <p className="hp-dr-recorded">
                  <strong>Still recorded:</strong> {s.opsec.still_recorded}
                </p>
                {s.opsec.tradeoff && (
                  <p>
                    <strong>Tradeoff:</strong> {s.opsec.tradeoff}
                  </p>
                )}
              </details>
            )}
          </article>
        ))}

        {catalog.data && catalog.data.signals.length > 0 && (
          <section className="hp-dr-signals">
            <h2 className="hp-dr-h">argument signals</h2>
            <p className="hp-dr-sub">
              Flags that change what a command looks like to a defender. Stealth-shaped
              arguments are <b>surfaced</b>, never advised.
            </p>
            <ul>
              {catalog.data.signals.map((g) => (
                <li key={g.id} className={g.stealth ? "is-stealth" : g.louder ? "is-louder" : ""}>
                  <code>{g.label}</code>
                  <span>{g.note}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        {src && (
          <p className="hp-dr-attr">
            {src.attack_attribution} · ATT&amp;CK {src.attack_version} · Sigma rules under{" "}
            {src.sigma_license}. Read-only: this surface annotates, it never runs anything.
          </p>
        )}
      </div>
    </PageShell>
  );
}
