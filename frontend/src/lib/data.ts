/**
 * Static content for the HackPit shell.
 * Numbers here are placeholders — real counts arrive when the backend is wired.
 */

export type Stat = {
  to: number;
  label: string;
};

export type NavItem = {
  key: string;
  label: string;
  active?: boolean;
};

export type AccentSwatch = {
  hex: string;
  title: string;
};

export type Category = {
  icon: string;
  color: string;
  title: string;
  desc: string;
  count?: number;
};

export const STATS: Stat[] = [
  { to: 276, label: "techniques" },
  { to: 72, label: "tools" },
  { to: 131, label: "workflows" },
  { to: 65, label: "screenshots ocr'd" },
];

export const NAV: NavItem[] = [
  { key: "recon", label: ":recon", active: true },
  { key: "ad", label: ":ad" },
  { key: "web", label: ":web" },
  { key: "privesc", label: ":privesc" },
  { key: "tools", label: ":tools" },
];

export const ACCENTS: AccentSwatch[] = [
  { hex: "#ffb03a", title: "amber" },
  { hex: "#b8f24a", title: "lime" },
  { hex: "#4fe0d0", title: "cyan" },
];

/** Placeholder entry count shown in the ⌘K affordance. */
export const ENTRY_COUNT = 431;

export const FEATURED = {
  icon: "↳",
  color: "#ffb03a",
  title: "Guided attack paths",
  badge: "new",
  desc: 'Type "how do I crack this box" — get an ordered recon → exploit → privesc walkthrough from your own notes.',
  cta: "start →",
};

export const CATEGORIES: Category[] = [
  {
    icon: "⬡",
    color: "#5dd3aa",
    title: "Active Directory",
    desc: "Kerberoasting, AS-REP, NTLM relay, ADCS, lateral movement.",
    count: 81,
  },
  {
    icon: "⚑",
    color: "#5aa9f0",
    title: "Web & bug bounty",
    desc: "SQLi, XSS, SSRF, IDOR, auth bypass, WAF evasion.",
    count: 26,
  },
  {
    icon: "◈",
    color: "#a996f5",
    title: "Recon & enum",
    desc: "Nmap, ffuf, dns, subdomains, service fingerprinting.",
    count: 56,
  },
  {
    icon: "▲",
    color: "#e88a5a",
    title: "Privilege escalation",
    desc: "SUID, capabilities, cron, kernel, Windows privesc.",
    count: 21,
  },
  {
    icon: "⚒",
    color: "#e0c15a",
    title: "Tools",
    desc: "Metasploit, mimikatz, chisel, ligolo, netexec, hashcat.",
    count: 72,
  },
  {
    icon: "⌂",
    color: "#6ad39a",
    title: "Post-exploitation",
    desc: "Persistence, pivoting, credential dumping, loot.",
    count: 7,
  },
];
