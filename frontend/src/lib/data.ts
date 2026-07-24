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
  { key: "library", label: ":library", href: "/" },
  { key: "attack-paths", label: ":attack-paths", href: "/attack-path" },
  { key: "cockpit", label: ":cockpit", href: "/cockpit" },
  { key: "kali", label: ":kali", href: "/kali" },
  { key: "engagements", label: ":engagements", href: "/engagements" },
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
