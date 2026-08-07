/**
 * Static UI content for the HackPit shell. Live numbers (stats, category
 * counts) come from the backend; this file holds only presentational copy.
 */

import type { Stats } from "./api";

export type NavItem = {
  key: string;
  label: string;
  /** Route this product section links to. */
  href: string;
};

export type AccentSwatch = {
  hex: string;
  title: string;
};

// Top-nav = PRODUCT SECTIONS, not KB categories. Category browsing (ad/web/
// privesc/tools/…) lives inside the library, driven by the live /categories
// counts — it does not belong in the top bar.
export const NAV: NavItem[] = [
  // (:library is the home view — reached via the wordmark, so it is not a nav tile.)
  { key: "attack-paths", label: ":attack-paths", href: "/attack-path" },
  { key: "cockpit", label: ":cockpit", href: "/cockpit" },
  // ONE shell tile. `:kali` opens the real PTY (vim/top/msfconsole render). The sentinel
  // "transcript shell" (clean, escape-free per-command records) is preserved at /kali —
  // reachable from the :kali page, just no longer its own top-nav tile.
  { key: "kali", label: ":kali", href: "/terminal" },
  // The OSCP inner loop (service+version -> CVE -> public exploit). A keyed lookup, so it
  // is its own surface rather than another mode of :library's prose search.
  { key: "exploits", label: ":exploits", href: "/exploits" },
  { key: "engagements", label: ":engagements", href: "/engagements" },
];

/** One launcher tile. `count` is looked up in HomeSummary.surfaces by `countKey`. */
export type Surface = {
  key: string;
  label: string;
  href: string;
  desc: string;
  /** Glyph on the tile — keeps a surface tile visually a sibling of a category card. */
  icon: string;
  /** Key into HomeSummary.surfaces. Omitted = no count badge. */
  countKey?: string;
  /** Shown as a small marker: this surface needs the docker stack up. */
  needsStack?: boolean;
};

export type SurfaceBand = {
  key: string;
  title: string;
  /** The safety posture of everything in the band — stated on the surface itself. */
  hint: string;
  color: string;
  surfaces: Surface[];
};

/**
 * THE LAUNCHER. Every route the app has, grouped by what it does to a target.
 *
 * This exists because roughly a dozen surfaces were reachable only by typing the
 * URL — :arsenal, :c2, :tunnels, :windows, :repeater, :scripts, :code-scan and the
 * AD graph were all built and then invisible. The top nav holds five product
 * sections and deliberately stays that size; this is the full index.
 *
 * The band `hint` is not decoration. It states the posture of everything in the
 * band, so the page cannot show a shell tile without also saying who approves it.
 */
export const SURFACE_BANDS: SurfaceBand[] = [
  {
    key: "plan",
    title: "plan",
    hint: "proposes · never executes",
    color: "#b8f24a",
    surfaces: [
      {
        key: "attack-paths",
        icon: "↳",
        label: ":attack-paths",
        href: "/attack-path",
        desc: "Ordered recon → exploit → privesc walkthrough from your notes.",
      },
      {
        key: "engagements",
        icon: "◱",
        label: ":engagements",
        href: "/engagements",
        desc: "Scoped targets, state, findings and exam reports.",
        countKey: "engagements",
      },
      {
        key: "ad-graph",
        icon: "⛁",
        label: ":ad-graph",
        href: "/cockpit/ad",
        desc: "BloodHound graph routed to Domain Admin, edge by edge.",
      },
      {
        key: "code-scan",
        icon: "◎",
        label: ":code-scan",
        href: "/code-scan",
        desc: "Static application-security review of a source tree.",
      },
      {
        key: "workflows",
        icon: "⧉",
        label: ":workflows",
        href: "/workflows",
        desc: "Compose reusable prompt-step playbooks over the code-audit fan-out.",
      },
    ],
  },
  {
    key: "operate",
    title: "operate",
    hint: "every command human-approved · needs the stack",
    color: "#4fe0d0",
    surfaces: [
      {
        key: "cockpit",
        icon: "▶",
        label: ":cockpit",
        href: "/cockpit",
        desc: "Guided loop — propose, approve, run, parse to state.",
        countKey: "sessions",
        needsStack: true,
      },
      // OPERATE, and the FRONT DOOR: give it a scoped domain and it runs recon as approved jobs,
      // seeds in-scope hosts/services/endpoints into engagement state, and ranks the surface by
      // likely-exploitable. One approval per sweep, ungated stop; discoveries can only ever widen
      // the allowed set WITHIN the declared scope — out-of-scope names stay read-only.
      {
        key: "recon",
        icon: "◈",
        label: ":recon",
        href: "/recon",
        desc: "Scoped domain → recon jobs → ranked attack surface. One approval per sweep.",
        needsStack: true,
      },
      {
        key: "terminal",
        icon: "▮",
        label: ":terminal",
        href: "/terminal",
        desc: "Real PTY inside the container. vim, top, msfconsole.",
        needsStack: true,
      },
      {
        key: "kali",
        icon: "$",
        label: ":kali",
        href: "/kali",
        desc: "Sentinel shell — clean, escape-free per-command records.",
        needsStack: true,
      },
      {
        key: "repeater",
        icon: "⇌",
        label: ":repeater",
        href: "/repeater",
        desc: "Craft and replay HTTP from inside the sandbox.",
        needsStack: true,
      },
      // OPERATE, not INFRASTRUCTURE, and the band hints are what decide it — they are a posture
      // claim about everything in the band, not decoration. Infrastructure reads "gated start ·
      // human-only stdin"; the proxy's start IS gated, but it has NO stdin at all (spawned
      // interactive=False, deliberately), so half that claim would be false for this tile.
      // Operate reads "every command human-approved · needs the stack", which is exactly true of
      // both halves: the gated start and the red-confirmed scan. Sitting next to :repeater also
      // makes the capture -> replay path discoverable, which is why the captured-exchange model
      // deliberately mirrors the repeater's field names.
      {
        key: "proxy",
        icon: "⊡",
        label: ":proxy",
        href: "/proxy",
        desc: "Record what your tools send — then actively scan it.",
        needsStack: true,
      },
      // OPERATE for the same reason the proxy is, and the hint is true of it exactly: the
      // intruder's start IS human-approved (the scanner's four gates, unchanged) and it needs
      // the stack. It sits next to :repeater and :proxy because that is the real path — capture
      // a request, replay it, then run a payload set through the one parameter that looked odd.
      {
        key: "intruder",
        icon: "⁂",
        label: ":intruder",
        href: "/intruder",
        desc: "One request, marked positions, a payload set — one approval.",
        needsStack: true,
      },
      // OPERATE, and the payoff of the whole state model: spray captured/OSINT creds across a
      // service, or crack captured hashes with a wordlist — one approval per job, an ungated
      // stop. A hit writes a validated credential + finding into state and marks the AD node
      // owned, which opens new frontier edges in :ad-graph.
      {
        key: "credentials",
        icon: "🔑",
        label: ":credentials",
        href: "/credentials",
        desc: "Spray captured creds, crack captured hashes — one approval per job.",
        needsStack: true,
      },
      // OPERATE, and the bug-bounty staple: point nuclei's template engine at the scoped
      // target(s) and turn matches into severity-ranked engagement findings. One approval buys
      // the whole scan (ffuf / ZAP-active-scan shape, no new gate), with an ungated stop.
      {
        key: "nuclei",
        icon: "◎",
        label: ":nuclei",
        href: "/nuclei",
        desc: "Template-scan the scoped target(s) — matches become findings, one approval.",
        needsStack: true,
      },
    ],
  },
  {
    key: "infrastructure",
    title: "infrastructure",
    hint: "gated start · human-only stdin",
    color: "#c98bff",
    surfaces: [
      {
        key: "c2",
        icon: "◉",
        label: ":c2",
        href: "/c2",
        desc: "Catch and drive one live shell. No multi-implant fleet.",
        needsStack: true,
      },
      {
        key: "tunnels",
        icon: "⇄",
        label: ":tunnels",
        href: "/tunnels",
        desc: "Pivots and DNS/TCP tunnels through the sandbox.",
        needsStack: true,
      },
      {
        key: "windows",
        icon: "⊞",
        label: ":windows",
        href: "/windows",
        desc: "Drive an external Windows/AD host over WinRM.",
        countKey: "windows_profiles",
      },
      {
        key: "evasion",
        icon: "◐",
        label: ":evasion",
        href: "/evasion",
        desc: "Generate-only payload shaping. Never auto-runs.",
        needsStack: true,
      },
      {
        key: "oob",
        icon: "◇",
        label: ":oob",
        href: "/oob",
        desc: "Canary for blind SSRF/XXE/RCE — the callback is the proof.",
      },
      {
        key: "exposure",
        icon: "⊙",
        label: ":exposure",
        href: "/exposure",
        desc: "Where a callback lands — a local interface, or a VPS redirector.",
      },
    ],
  },
  {
    key: "reference",
    title: "reference",
    hint: "read-only · no stack required",
    color: "#ffb03a",
    surfaces: [
      {
        key: "exploits",
        icon: "⌁",
        label: ":exploits",
        href: "/exploits",
        desc: "Service + version → CVE → public exploit lookup.",
      },
      {
        key: "arsenal",
        icon: "⚒",
        label: ":arsenal",
        href: "/arsenal",
        desc: "Catalogued tools with vetted invocation templates.",
        countKey: "arsenal",
      },
      {
        key: "scripts",
        icon: "≡",
        label: ":scripts",
        href: "/scripts",
        desc: "Reusable one-liners and enumeration snippets.",
        countKey: "scripts",
      },
      {
        key: "detection",
        icon: "◉",
        label: ":detection",
        href: "/detection",
        desc: "The curated ATT&CK / Sigma map — what a defender sees.",
      },
    ],
  },
];

export const ACCENTS: AccentSwatch[] = [
  { hex: "#ffb03a", title: "amber" },
  { hex: "#b8f24a", title: "lime" },
  { hex: "#4fe0d0", title: "cyan" },
];

/** Pre-load fallback for the ⌘K affordance; TopBar shows the live /stats
 * total_entries once loaded. Kept roughly current so the flash isn't stale. */
export const ENTRY_COUNT = 1551;

/** The home counters, in order, mapped to /stats fields. */
export const STAT_FIELDS: { key: keyof Stats; label: string }[] = [
  { key: "techniques", label: "techniques" },
  { key: "tools", label: "tools" },
  { key: "workflows", label: "workflows" },
];

/** Featured bento card — the guided-attack-paths surface. */
export const FEATURED = {
  icon: "↳",
  color: "#ffb03a",
  title: "Guided attack paths",
  badge: "new",
  desc: 'Type "how do I crack this box" — get an ordered recon → exploit → privesc walkthrough from your own notes.',
  cta: "start →",
};

/** Featured bento card — the Cockpit (sibling of the attack-paths card). */
export const COCKPIT_FEATURE = {
  icon: "▸",
  color: "#ffb03a",
  title: "Cockpit",
  badge: "new",
  desc: "Plot a path, then run it — approved commands in an isolated sandbox, live output.",
  cta: "start →",
};

/**
 * Short blurbs per category slug, so the bento cards keep the mock's copy.
 * Categories without a blurb fall back to an entry count line.
 */
export const CATEGORY_BLURBS: Record<string, string> = {
  "active-directory": "Kerberoasting, AS-REP, NTLM relay, ADCS, lateral movement.",
  web: "SQLi, XSS, SSRF, IDOR, auth bypass, WAF evasion.",
  recon: "Nmap, ffuf, dns, subdomains, service fingerprinting.",
  privesc: "SUID, capabilities, cron, kernel, Windows privesc.",
  tools: "Metasploit, mimikatz, chisel, ligolo, netexec, hashcat.",
  "post-exploitation": "Persistence, pivoting, credential dumping, loot.",
  services: "Per-service enumeration & exploitation playbooks.",
  credentials: "Hashes, cracking, spraying, credential reuse.",
  persistence: "Footholds, backdoors, scheduled tasks, autoruns.",
  exploitation: "Public exploits, PoCs, initial access.",
  reference: "Cheatsheets, mappings, quick-reference material.",
  wireless: "Wi-Fi capture, cracking, and rogue AP attacks.",
};

export function categoryBlurb(slug: string, count: number): string {
  return CATEGORY_BLURBS[slug] ?? `${count} ${count === 1 ? "entry" : "entries"}.`;
}
