import type { AttackPath } from "./api";

/**
 * A realistic sample attack-path used to demo the cockpit map when no path has
 * been composed yet (and for offline development). Its shape is identical to a
 * live POST /attack-path response; the cockpit view labels it "sample" so it is
 * never mistaken for a live run. Content mirrors real web-app methodology so the
 * visualization is faithful (grounded + ai_suggested steps, branches, a skipped
 * privesc phase, a target profile HUD).
 */
export const COCKPIT_SAMPLE: AttackPath = {
  goal: "web app bug bounty — modern JS storefront",
  target_type: "bugbounty",
  target: "shop.target.tld",
  origin: "composed",
  model_used: "sample",
  provider: "sample",
  box_writeup: null,
  scoped: false,
  profile: {
    target_class: "web application",
    tech_signals: ["Node.js", "Express", "Angular", "REST API"],
    priority_bug_classes: ["IDOR", "SQL injection", "XSS", "SSRF", "JWT flaws"],
    out_of_scope: [],
  },
  phases: [
    {
      phase: "recon",
      label: "Recon",
      steps: [
        {
          id: "recon-1",
          title: "Subdomain & asset discovery",
          entry_id: "subdomain-enumeration",
          why: "Map the full external surface before touching the app — forgotten hosts and staging subdomains are where the soft targets live.",
          commands: [
            { lang: "bash", cmd: "subfinder -d target.tld -all -silent | httpx -sc -title", copyable: true },
          ],
          target_adaptation: "Seed with shop.target.tld and pivot to any api./staging. hosts it turns up.",
        },
        {
          id: "recon-2",
          title: "Fingerprint the web stack",
          entry_id: "web-tech-fingerprint",
          why: "Knowing it's Express + Angular narrows the bug classes worth chasing (client-side routing, REST IDOR, JWT).",
          commands: [
            { lang: "bash", cmd: "whatweb -a 3 https://shop.target.tld", copyable: true },
          ],
        },
      ],
    },
    {
      phase: "enumeration",
      label: "Enumeration",
      steps: [
        {
          id: "enumeration-1",
          title: "Directory & endpoint discovery",
          entry_id: "content-discovery-ffuf",
          why: "Surface hidden API routes and admin panels the SPA never links to.",
          commands: [
            { lang: "bash", cmd: "ffuf -u https://shop.target.tld/FUZZ -w raft-medium.txt -mc 200,301,401", copyable: true },
          ],
          on_blocked: "If a WAF starts 403ing, drop -rate and rotate to a residential proxy.",
        },
        {
          id: "enumeration-2",
          title: "Parameter mining on the REST API",
          entry_id: "",
          why: "Hidden parameters on /rest endpoints often gate the IDOR and mass-assignment bugs.",
          ai_suggested: true,
          commands: [
            { lang: "bash", cmd: "arjun -u https://shop.target.tld/rest/user/whoami", copyable: true },
          ],
        },
      ],
    },
    {
      phase: "exploitation",
      label: "Exploitation",
      steps: [
        {
          id: "exploitation-1",
          title: "IDOR on object references",
          entry_id: "idor-object-reference",
          why: "Sequential /rest/basket/{id} and /api/orders/{id} ids are the highest-signal bug class for this stack.",
          from_writeup: false,
          commands: [
            { lang: "bash", cmd: "curl -s https://shop.target.tld/rest/basket/2 -H \"Authorization: Bearer $TOKEN\"", copyable: true },
          ],
          target_adaptation: "Log in as a low-priv user, note your own basket id, then decrement/increment it.",
          on_success: "Cross-tenant read confirmed → escalate to write (add items to another user's basket) for max impact.",
        },
        {
          id: "exploitation-2",
          title: "SQL injection in product search",
          entry_id: "sqli-error-based",
          why: "Legacy search endpoints on Express apps frequently concatenate the q parameter straight into the query.",
          commands: [
            { lang: "bash", cmd: "sqlmap -u \"https://shop.target.tld/rest/products/search?q=apple\" --batch --risk 2", copyable: true },
          ],
          on_blocked: "If parameterized, pivot to the login endpoint's email field and retry with --technique=B.",
        },
        {
          id: "exploitation-3",
          title: "Stored XSS via review body",
          entry_id: "",
          why: "User-controlled review text rendered without encoding is a classic stored-XSS sink in these SPAs.",
          ai_suggested: true,
          commands: [
            { lang: "html", cmd: "<iframe src=\"javascript:alert(document.domain)\">", copyable: true },
          ],
        },
      ],
    },
    {
      phase: "privesc",
      label: "Privilege Escalation",
      steps: [],
    },
    {
      phase: "post-exploitation",
      label: "Post-Exploitation",
      steps: [
        {
          id: "post-exploitation-1",
          title: "Forge a privileged JWT",
          entry_id: "jwt-alg-confusion",
          why: "If the API signs with a weak/HS256 secret or accepts alg:none, mint an admin token from a captured one.",
          commands: [
            { lang: "bash", cmd: "jwt_tool $TOKEN -X a -I -pc role -pv admin", copyable: true },
          ],
          on_success: "Admin token accepted → demonstrate access to /rest/admin, then stop and write it up.",
        },
      ],
    },
  ],
};
