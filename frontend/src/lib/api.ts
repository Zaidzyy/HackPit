/**
 * Typed client for the HackPit backend.
 *
 * Base URL comes from NEXT_PUBLIC_API_URL (default http://localhost:8000).
 * All calls run in the browser, so the frontend build never depends on the
 * backend being up — pages fetch on mount and render loading / error states.
 */

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ---- response shapes (mirror the FastAPI models) ------------------------- //

export type Stats = {
  techniques: number;
  tools: number;
  workflows: number;
  screenshots_ocr: number;
  total_entries: number;
  categories: number;
};

export type Category = {
  slug: string;
  name: string;
  count: number;
  color: string;
  icon: string;
};

/** Status rail for the launcher. Mirrors the backend's `HomeRail` — statuses only,
 *  never a secret (`llm_model` is the model name; the API key is never sent). */
export type HomeRail = {
  /** null when the probe could not determine it (docker missing, probe timed out). */
  sandbox_up: boolean | null;
  engage_sandbox_up: boolean | null;
  llm_provider: string;
  llm_model: string;
  windows_profile: string | null;
  engagement_id: string | null;
  engagement_target: string | null;
};

export type Operator = {
  /** Empty string when unconfigured — render no byline rather than an empty one. */
  name: string;
  handle: string;
};

export type HomeSummary = {
  rail: HomeRail;
  /** Surface id -> count for the tile badges. Absent id = no badge. */
  surfaces: Record<string, number>;
};

export type EntrySummary = {
  id: string;
  title: string;
  summary: string;
  tags: string[];
  tier: number;
  source: string;
  /** Short friendly source label for the chip (e.g. "sec", "HackTricks"). */
  source_label: string;
  category: string;
  /** Distinct sources consolidated into this entry (>=1). */
  source_count: number;
};

export type Code = {
  lang: string;
  cmd: string;
  copyable: boolean;
};

export type Step = {
  n: number;
  text: string;
  code: Code[];
  images: string[];
};

/** One image's ingest metadata (kind, OCR length, machine caption). */
export type MetaImage = {
  path: string;
  kind?: string;
  char_count?: number;
  ocr_len?: number;
  caption?: string;
  caption_source?: string;
};

export type Entry = {
  id: string;
  title: string;
  category: string;
  subcategory: string | null;
  source: string;
  tier: number;
  tags: string[];
  tools: string[];
  summary: string;
  steps: Step[];
  body_md: string;
  references: string[];
  meta: Record<string, unknown>;
  schema_version: string;
  // ---- resolved source-provenance facets (added by GET /entry) ---------- //
  /** Short friendly label for the spine source (e.g. "your notes", "sec"). */
  primary_source_label: string;
  /** Full attribution for the spine source, shown as a tooltip. */
  primary_source_full: string;
  /** Friendly labels for the other sources folded in (spine excluded). */
  also_covered_in_labels: string[];
  /** Distinct sources covering this entry (>=1). */
  source_count: number;
  /** True when the entry's tested content is your own notes. */
  from_your_notes: boolean;
  /** Labelled technique variants recorded during consolidation. */
  variants: string[];
};

/** One ranked search result (snippet emphasises matches with **markers**). */
export type SearchHit = {
  rank: number;
  score: number;
  id: string;
  title: string;
  category: string;
  source: string;
  /** Short friendly source label for the chip (e.g. "sec", "HackTricks"). */
  source_label: string;
  tier: number | null;
  snippet: string;
  /** Distinct sources consolidated into this entry (>=1). */
  source_count: number;
};

export type SearchResponse = {
  query: string;
  /** Mode actually used ("hybrid" | "lexical" | "vector"). */
  mode: string;
  requested_mode: string;
  /** True when the requested mode degraded to lexical (e.g. Ollama down). */
  fell_back: boolean;
  count: number;
  results: SearchHit[];
};

// ---- guided attack paths (generative) ------------------------------------ //

/** LLM provider config as the browser is allowed to see it (never the key). */
export type LLMConfig = {
  /** ollama | openai | anthropic | openrouter */
  provider: string;
  model: string;
  /** Whether a key is stored server-side. The key itself is never returned. */
  has_key: boolean;
};

/**
 * A command as the PLANNER returns it — the KB's `Code` plus what composition learned
 * about it. Separate from `Code` because these facts are true of a *planned* command,
 * not of a stored KB one.
 */
export type PlannedCode = Code & {
  /** The model's own command (an ai_suggested step) — nothing checked that it works. */
  unverified?: boolean;
  /** Capped for display; open the cited entry for the full text. */
  truncated?: boolean;
  /**
   * THE SCOPE CHECK. `false` = this cannot run as written against this engagement (see
   * unrunnable_reason). Absent/null = it names an in-scope host, or there was no declared
   * scope to check against. Plan quality only — it refuses nothing; the executor's
   * target/scope lock is the real bound.
   */
  runnable?: boolean | null;
  /** Why it cannot run: an out-of-scope host, or no host at all. */
  unrunnable_reason?: string | null;
  /**
   * The command as the KB stored it — present ONLY when HackPit repointed it at your target,
   * so a rewrite is visible rather than silent.
   */
  original_cmd?: string | null;
  /** The out-of-scope host(s) replaced to produce `cmd`. Target-directed tools only. */
  repointed_from?: string[] | null;
  /**
   * What this command would look like pointed at your target — offered for a FLAGGED command
   * the automatic pass declined to rewrite (curl, wget, nc, ssh…, where the host may be a
   * tool download or your own listener). NEVER applied: the UI shows it BESIDE the original,
   * because the reason the automatic pass declined is that only a human can tell which.
   */
  suggested_cmd?: string | null;
  /** The host(s) `suggested_cmd` would replace. */
  suggested_from?: string[] | null;
};

/** One grounded step of a composed attack path. */
export type AttackStep = {
  /** Stable id ("{phase}-{n}") — safe to key engagement/check-off state on. */
  id: string;
  title: string;
  /** Cited KB entry — links to /entry/{entry_id}. Empty for an AI-suggested step. */
  entry_id: string;
  why: string;
  /**
   * Commands for this step. Grounded/writeup steps carry the entry's real
   * commands; AI-suggested steps carry the model's own, unverified.
   */
  commands: PlannedCode[];
  /**
   * How many of this step's commands failed the scope check — a badge count, so a step
   * can be seen to need work without expanding it. Absent when none did.
   */
  unrunnable_commands?: number;
  /**
   * True = general-knowledge gap-fill, NOT from the KB (render distinctly with a
   * "verify" badge). False/absent = grounded in the KB or the user's writeup.
   */
  ai_suggested?: boolean;
  /**
   * True = a PRIMARY step from the user's own box writeup (trusted). Absent/false
   * = a composed or supplement step.
   */
  from_writeup?: boolean;
  /**
   * Optional one-line "adapt to this target" guidance for a grounded step —
   * bridges the technique's generic example commands to THIS target by naming real
   * hosts/endpoints/accounts from the goal/scope. Prose guidance, NOT a runnable
   * command; the step's real commands are unchanged. Absent when it couldn't be
   * adapted confidently.
   */
  target_adaptation?: string;
  /**
   * HONESTY MARKER — hosts / AD domains still named in this step's commands that are
   * NOT the engagement's target and could not be confidently rewritten (a KB command
   * written for another environment: `MARVEL.local`, `192.168.1.10`). The step needs
   * adjusting before it runs. Nothing is guessed in their place — a fabricated domain
   * would be worse than a visible gap. Absent when nothing foreign is referenced.
   */
  foreign_refs?: string[];
  /**
   * Optional branch hints (static, pre-execution). on_success = what this finding
   * unlocks / the next action; on_blocked = the pivot if it 403s or fails. Present
   * only where the model saw a real decision point.
   */
  on_success?: string;
  on_blocked?: string;
  /**
   * DETECTION FOOTPRINT TAG (purple-team). The ATT&CK technique(s) + tactic this
   * step's first command maps to, plus a loud-vs-quiet rating — what a DEFENDER
   * would see if the step ran. Null/absent when the curated map doesn't cover the
   * command (the drawer can still fetch an ai_suggested reading on demand).
   */
  attck?: DetectionTag | null;
  /**
   * TOOL ARSENAL PROVENANCE — which catalogued tool this step actually runs, read from
   * the command's own program name (never from anything the model claimed). Null when
   * the step runs no catalogued tool. Informational only: it is not a claim that the
   * command was verified, and it changes nothing about how the step runs.
   */
  arsenal?: ArsenalTag | null;
};

/** The catalogued tool a step runs — see /arsenal. */
export type ArsenalTag = {
  /** The step's primary catalogued tool — the first one it runs. */
  tool: string;
  /** Every catalogued tool the step runs, in command order. */
  tools?: string[];
  category: string;
  purpose: string;
  /** KB entry documenting this tool, when one exists. */
  kb_entry_id: string | null;
  docs: string;
};

export type AttackPhase = {
  /** recon | enumeration | exploitation | privesc | post-exploitation */
  phase: string;
  label: string;
  steps: AttackStep[];
};

/** A full box writeup surfaced as a link above a composed path (never as steps). */
export type BoxWriteup = {
  id: string;
  title: string;
  tier: number;
};

/**
 * What KIND of target this is — inferred before retrieval so the path probes the
 * right bug classes. Drives the "why these steps" chips above the path. All
 * fields empty when the profiler was unavailable.
 */
export type TargetProfile = {
  target_class: string | null;
  tech_signals: string[];
  priority_bug_classes: string[];
  out_of_scope: string[];
};

/** A document injected into the planner's prompt as reasoning background. */
export type ContextSource = {
  kind: "writeup" | "methodology";
  id: string;
  title: string;
  /** Size of the injected excerpt — the retrieval is budgeted, not the whole doc. */
  chars: number;
};

export type AttackPath = {
  goal: string;
  target_type: string | null;
  /** Target (IP/host/URL) substituted into commands; null if none could be determined. */
  target: string | null;
  /**
   * Where that target came from — "caller" (the request's own target field), "goal"
   * (parsed out of the goal text) or "scope" (the first concrete in-scope host, which
   * HackPit chose for you). Null when there is no target at all, in which case no
   * example host was rewritten and most commands will come back unrunnable.
   */
  target_source?: "caller" | "goal" | "scope" | null;
  /**
   * True when a usable scope was supplied and every command was judged against it.
   * Reported separately from the count because "0 of 0 checked" and "0 of 32 bad" are
   * the same number and very different facts — without this the UI renders unchecked
   * as clean.
   */
  scope_checked?: boolean;
  /** How many commands this path returned, across every step. */
  commands_total?: number;
  /**
   * How many were automatically repointed at your target — an out-of-scope host replaced in
   * a TARGET-DIRECTED tool's argument. Fetch-capable tools are never repointed automatically.
   */
  commands_repointed?: number;
  /**
   * THE HONESTY NUMBER — how many of them cannot run as written: they point at a host
   * outside the scope, or name no host at all. A plan built from the KB's own example
   * commands used to be indistinguishable from one adapted to the target. Always 0 when
   * no scope was pasted, because then nothing was checked — that is "unchecked", not
   * "clean", and the banner says so.
   */
  commands_unrunnable?: number;
  phases: AttackPhase[];
  /** Inferred target profile that steered this path (chips show target_class +
   * priority_bug_classes). Empty when the profiler was unavailable. */
  profile?: TargetProfile;
  /** True when steps were dropped for touching an out-of-scope path/host. */
  scoped?: boolean;
  /**
   * Set when the goal named a box we have a writeup for. It's the link target,
   * and the SOURCE of the path when origin === "writeup".
   */
  box_writeup: BoxWriteup | null;
  /**
   * "writeup" = path built from the user's own box walkthrough (trusted steps);
   * "composed" = KB-grounded + AI-suggested composition.
   */
  origin?: "writeup" | "composed";
  /** Banner label when origin === "writeup", e.g. "from your writeup: Voleur". */
  origin_label?: string | null;
  /** Caveat, e.g. a "source formatting damaged" note for a mangled writeup. */
  origin_note?: string | null;
  /** Writeup origin: true when supplement steps were added beyond the writeup. */
  augmented?: boolean;
  /**
   * Channel 2 — the documents the planner READ as background (a matched box
   * writeup's approach, the methodology docs for this goal). They shaped
   * technique choice and the plan's flow; none of them became a step, and none
   * of them changes a step's grounded/ai_suggested label. Empty when nothing
   * matched, in which case the composition is identical to pre-Channel-2.
   */
  context_sources?: ContextSource[];
  /** Box-specific literals from that background caught in the model's output
   * and re-pointed at the target or dropped (plan quality; the executor's
   * target/scope lock is the safety backstop). */
  context_leaks?: number;
  /** Model that composed the path (e.g. "qwen3:8b"); "your writeup" for writeups. */
  model_used: string;
  provider: string;
};

// ---- fetch plumbing ------------------------------------------------------ //

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Pull a human-readable message out of a FastAPI error body, if present. */
async function errorMessage(res: Response, fallback: string): Promise<string> {
  try {
    const body = (await res.json()) as {
      detail?: string | { gate?: string; reason?: string };
    };
    if (typeof body?.detail === "string" && body.detail.trim()) {
      return body.detail;
    }
    // Cockpit gate rejections carry { detail: { gate, reason } }. Surface them as
    // "[gate] reason" so callers can key off the gate (e.g. the session panel's
    // "[danger]" red-confirm) instead of getting a generic "Request failed".
    if (body?.detail && typeof body.detail === "object") {
      const { gate, reason } = body.detail;
      if (gate || reason) return `[${gate ?? "error"}] ${reason ?? ""}`.trim();
    }
  } catch {
    /* non-JSON body — use the fallback */
  }
  return fallback;
}

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      headers: { Accept: "application/json" },
      signal,
    });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    if (res.status === 404) throw new ApiError(404, "Not found.");
    throw new ApiError(res.status, `Request failed (${res.status}).`);
  }
  return (await res.json()) as T;
}

async function postJSON<T>(
  path: string,
  body: unknown,
  signal?: AbortSignal
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
      signal,
    });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    throw new ApiError(
      res.status,
      await errorMessage(res, `Request failed (${res.status}).`)
    );
  }
  return (await res.json()) as T;
}

async function sendJSON<T>(
  method: "PATCH" | "PUT" | "DELETE",
  path: string,
  body?: unknown,
  signal?: AbortSignal
): Promise<T | null> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      method,
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    throw new ApiError(
      res.status,
      await errorMessage(res, `Request failed (${res.status}).`)
    );
  }
  if (res.status === 204) return null;
  return (await res.json()) as T;
}

export const getStats = (signal?: AbortSignal) =>
  getJSON<Stats>("/stats", signal);

export const getCategories = (signal?: AbortSignal) =>
  getJSON<Category[]>("/categories", signal);

/**
 * Launcher status rail. Fetched SEPARATELY from /stats on purpose: this endpoint
 * runs docker probes, so putting it on the hero's critical path would gate the
 * counters behind a container inspect. The rail renders "checking…" until it lands.
 */
export const getHomeSummary = (signal?: AbortSignal) =>
  getJSON<HomeSummary>("/home-summary", signal);

/** Who is running this HackPit. Name + handle only — the OSID/email in the
 *  operator config are report-only and are never served to the browser. */
export const getOperator = (signal?: AbortSignal) =>
  getJSON<Operator>("/operator", signal);

export const getCategory = (slug: string, signal?: AbortSignal) =>
  getJSON<EntrySummary[]>(`/categories/${encodeURIComponent(slug)}`, signal);

export const getEntry = (id: string, signal?: AbortSignal) =>
  getJSON<Entry>(`/entry/${encodeURIComponent(id)}`, signal);

/** URL for a note screenshot served by the backend's sandboxed /image route. */
export const imageUrl = (path: string) =>
  `${API_URL}/image?path=${encodeURIComponent(path)}`;

// ---- scripts arsenal ----------------------------------------------------- //

/** One entry a script was lifted from (links to /entry/{id}). */
export type ScriptSource = { id: string; title: string; category: string };

/**
 * A tool FILE on disk rather than a copyable snippet (`oscp_tools`, D12).
 * Present only on rows the corpus ingester contributed — the row's `code` is a
 * short preview, so the UI offers a path to copy, not a payload.
 */
export type ScriptFile = {
  name: string;
  rel_path: string;
  host_path: string;
  bytes: number;
  sha256: string;
  /** windows | linux | any */
  platform: string;
  /** false for Windows-only tooling — kept for planning/write-ups, never runnable here. */
  runs_here: boolean;
  source: string;
};

/** One deduped, copy-ready script/payload in the arsenal. */
export type ScriptItem = {
  id: string;
  label: string;
  lang: string;
  code: string;
  type: string;
  /** How many entries this script appears in. */
  reuse: number;
  sources: ScriptSource[];
  source_total: number;
  /** Set when this row is a tool file rather than an extracted snippet. */
  file?: ScriptFile | null;
};

export type ScriptGroup = {
  type: string;
  label: string;
  icon: string;
  color: string;
  count: number;
  shown: number;
  scripts: ScriptItem[];
};

export type ScriptsResponse = {
  total: number;
  kb_entries: number;
  /** Rows backed by a file on disk rather than extracted from KB text. */
  tool_files?: number;
  groups: ScriptGroup[];
};

/** Group counts only (no script bodies) — feeds the home card. */
export type ScriptsSummary = {
  total: number;
  groups: { type: string; label: string; icon: string; color: string; count: number }[];
};

export const getScripts = (signal?: AbortSignal) =>
  getJSON<ScriptsResponse>("/scripts", signal);

export const getScriptsSummary = (signal?: AbortSignal) =>
  getJSON<ScriptsSummary>("/scripts/summary", signal);

export const search = (
  q: string,
  opts: { mode?: string; top?: number } = {},
  signal?: AbortSignal
) => {
  const { mode = "hybrid", top = 20 } = opts;
  const params = new URLSearchParams({ q, mode, top: String(top) });
  return getJSON<SearchResponse>(`/search?${params.toString()}`, signal);
};

// ---- guided attack paths + LLM config ------------------------------------ //

export const getLLMConfig = (signal?: AbortSignal) =>
  getJSON<LLMConfig>("/llm-config", signal);

/** Persist provider/model (+ optional key). The key is sent ONCE and never
 *  stored in the browser — the response only reports whether a key is held. */
export const setLLMConfig = (
  cfg: { provider: string; model?: string; api_key?: string },
  signal?: AbortSignal
) => postJSON<LLMConfig>("/llm-config", cfg, signal);

/** Model names pulled in the local Ollama, for the settings picker. Returns an
 *  empty list when Ollama is unreachable (the picker degrades to free text). */
export const getOllamaModels = (signal?: AbortSignal) =>
  getJSON<{ models: string[] }>("/ollama-models", signal);

/**
 * Compose a guided attack path. Slow: the local model can take a minute+.
 *
 * `target` is optional and explicit — it overrides the target parsed from the goal and is
 * what example hosts in KB commands get rewritten to. Omitted, the target comes from the
 * goal, and failing that from the first concrete host in `scope_text`. The endpoint
 * rejects unknown fields (422) rather than dropping them, so a typo here is visible.
 */
export const composeAttackPath = (
  goal: string,
  target_type?: string | null,
  scope_text?: string | null,
  signal?: AbortSignal,
  target?: string | null
) =>
  postJSON<AttackPath>(
    "/attack-path",
    {
      goal,
      target_type: target_type ?? null,
      scope_text: scope_text ?? null,
      target: target ?? null,
    },
    signal
  );

// ---- engagement sessions -------------------------------------------------- //

/** A saved session's step: an attack step plus its persisted engagement state. */
export type EngagementStep = AttackStep & {
  checked: boolean;
  result_text: string;
};

export type EngagementPhase = {
  phase: string;
  label: string;
  steps: EngagementStep[];
};

/** The composed path as stored in a session, with per-step state merged in. */
export type EngagementPath = {
  goal: string;
  target_type: string | null;
  target?: string | null;
  phases: EngagementPhase[];
  model_used: string;
  provider: string;
};

/** One turn of the engagement assistant conversation. */
export type ChatTurn = {
  role: "user" | "assistant";
  content: string;
  ts: string;
  /** KB entries the assistant cited (assistant turns only) — link to /entry/{id}. */
  cited_entry_ids?: string[];
};

/** Full engagement session (GET /sessions/{id}). */
export type Session = {
  id: string;
  label: string;
  goal: string;
  target_type: string | null;
  created_at: string;
  updated_at: string;
  checked: number;
  total: number;
  path: EngagementPath;
  /** Last generated report (Markdown) + when, if any. */
  report_md: string | null;
  report_generated_at: string | null;
  /** The model that actually generated the persisted report; null for reports
   *  saved before model attribution was persisted (UI falls back to config). */
  report_model: string | null;
  /**
   * SUBMISSION FIELDS — what the bug-bounty report renders alongside the finding. Set them
   * on the engagement screen; the report screen echoes what it will use.
   */
  /** CVSS 3.1 vector. The SCORE is computed from it at report time, never asserted. */
  cvss_vector: string | null;
  /** Bugcrowd VRT category key (see getVRTCategories) — maps to P1–P5 by LOOKUP. */
  vrt_category: string | null;
  /**
   * The program's published known-issues list, pasted verbatim from the brief. At report
   * time each finding is compared against it and possible matches are FLAGGED — never
   * auto-suppressed, because a false match that silently dropped a real finding would cost
   * far more than a warning you dismiss.
   */
  known_issues: string | null;
  /** The engagement assistant's persisted conversation. */
  chat_history: ChatTurn[];
};

/** The assistant's reply to one chat message (POST /sessions/{id}/chat). */
export type ChatReply = {
  reply: string;
  cited_entry_ids: string[];
  model_used: string;
  ts: string;
};

/** A freshly generated report (POST /sessions/{id}/report). */
export type Report = {
  report_md: string;
  report_generated_at: string;
  model_used: string;
};

/** Session list row (GET /sessions). */
export type SessionSummary = {
  id: string;
  label: string;
  goal: string;
  target_type: string | null;
  checked: number;
  total: number;
  created_at: string;
  updated_at: string;
};

export type StepState = { checked: boolean; result_text: string };

/** Create a saved engagement from a composed path. Returns the new id. */
export const createSession = (
  path: AttackPath,
  signal?: AbortSignal
) =>
  postJSON<{ id: string }>(
    "/sessions",
    { goal: path.goal, target_type: path.target_type, path },
    signal
  );

export const listSessions = (signal?: AbortSignal) =>
  getJSON<SessionSummary[]>("/sessions", signal);

export const getSession = (id: string, signal?: AbortSignal) =>
  getJSON<Session>(`/sessions/${encodeURIComponent(id)}`, signal);

/** Partially update one step's state (checked and/or pasted result). */
export const updateStep = (
  sessionId: string,
  stepId: string,
  patch: { checked?: boolean; result?: string },
  signal?: AbortSignal
) =>
  sendJSON<StepState>(
    "PATCH",
    `/sessions/${encodeURIComponent(sessionId)}/steps/${encodeURIComponent(stepId)}`,
    patch,
    signal
  ) as Promise<StepState>;

export const renameSession = (
  id: string,
  label: string,
  signal?: AbortSignal
) =>
  sendJSON<SessionSummary>(
    "PATCH",
    `/sessions/${encodeURIComponent(id)}`,
    { label },
    signal
  ) as Promise<SessionSummary>;

export const deleteSession = (id: string, signal?: AbortSignal) =>
  sendJSON<null>("DELETE", `/sessions/${encodeURIComponent(id)}`, undefined, signal);

// ---- submission fields (bug-bounty report) -------------------------------- //

/** One Bugcrowd VRT category HackPit can map to a P1–P5 priority (GET /vrt-categories). */
export type VRTCategory = {
  /** The key stored on the engagement, e.g. "xss-stored". */
  key: string;
  /** P1 | P2 | P3 | P4 | P5 */
  priority: string;
  /** The VRT path, e.g. "Cross-Site Scripting (XSS) > Stored > Non-Self". */
  category: string;
  /** What the priority means to a triager, in one clause. */
  meaning: string;
};

/**
 * The VRT categories, for a picker. A CURATED SUBSET of the taxonomy at its default
 * priorities — not the full VRT, and a program's own brief overrides it. The priority is a
 * LOOKUP on the category and is never derived from the CVSS score: the two genuinely
 * disagree, and a triager acts on the VRT one.
 */
export const getVRTCategories = (signal?: AbortSignal) =>
  getJSON<{ categories: VRTCategory[] }>("/vrt-categories", signal);

/**
 * Set the CVSS vector, VRT category and/or known-issues list for an engagement.
 *
 * Only the fields you pass are written, so one can be updated without clearing the others;
 * an EMPTY STRING clears a field. Values are stored verbatim and unvalidated on purpose — an
 * unparseable vector and an unrecognised VRT key are both reported IN THE REPORT, where you
 * will see them, rather than rejected here where what you typed would be lost.
 */
export const setSubmission = (
  id: string,
  fields: {
    cvss_vector?: string | null;
    vrt_category?: string | null;
    known_issues?: string | null;
  },
  signal?: AbortSignal
) =>
  sendJSON<Session>(
    "PATCH",
    `/sessions/${encodeURIComponent(id)}/submission`,
    fields,
    signal
  ) as Promise<Session>;

/** The exam/format template for a generated report. */
export type ReportTemplate = "standard" | "oscp" | "cpts" | "bugbounty";

/** Draft (or re-draft) a pentest report for the session. Slow on local models.
 *  `template` selects the exam/format mode; `includeOpsec` adds the red-team OPSEC assessment. */
export const generateReport = (
  id: string,
  template: ReportTemplate = "standard",
  includeOpsec = false,
  signal?: AbortSignal
) =>
  postJSON<Report>(
    `/sessions/${encodeURIComponent(id)}/report?template=${template}&include_opsec=${includeOpsec}`,
    {},
    signal
  );

/** Record a captured local.txt/proof.txt flag against a host (drives the OSCP report table). */
export const setProof = (
  id: string,
  body: { address: string; kind: "local" | "proof"; value: string },
  signal?: AbortSignal
) =>
  postJSON<{ address: string; local_txt: string; proof_txt: string; ownership: string }>(
    `/sessions/${encodeURIComponent(id)}/state/proof`,
    body,
    signal
  );

/** Ask the engagement assistant one question. Slow: the local model composes
 *  a grounded reply from the session context + KB (can take 20-60s). */
export const sendChat = (id: string, message: string, signal?: AbortSignal) =>
  postJSON<ChatReply>(
    `/sessions/${encodeURIComponent(id)}/chat`,
    { message },
    signal
  );

// ---- Cockpit (live, human-approved execution against the isolated lab) ---- //

export type CockpitCommand = {
  name: string;
  description: string;
  allowed_flags: string[];
};

export type CockpitAllowlist = {
  commands: CockpitCommand[];
  lab_target: string;
};

export type CockpitStatus = {
  sandbox: string;
  lab_target: string;
  up: boolean;
  isolated: boolean;
  ready: boolean;
  detail: string;
};

export type CockpitRun = {
  run_id: string;
  command: string;
  args: string[];
  target: string;
  approved: boolean;
  /** "lab" (isolated lab), "engagement" (real authorized target), or "windows" (a
   *  PowerShell command run on a Windows target over WinRM). */
  mode?: "lab" | "engagement" | "windows";
  exit_code: number | null;
  stdout: string;
  stderr: string;
  started_at: string;
  finished_at: string | null;
  session_id: string | null;
  step_id: string | null;
};

/** One streamed execution event (SSE `data:` payload from POST /cockpit/exec). */
export type ExecEvent =
  | {
      type: "start";
      run_id: string;
      command: string;
      args: string[];
      target: string;
      mode?: "lab" | "engagement" | "windows";
      transport?: string;
      started_at: string;
      /**
       * How this run was rewritten before it started, in the operator's words — and
       * crucially INCLUDING the cases where it was not. "curl has no known throttle flag —
       * this run was NOT paced" has to be read before the output arrives, or a full-speed
       * run gets mistaken for a paced one. Empty when nothing was asked for.
       */
      notes?: string[];
    }
  | { type: "stdout"; line: string }
  | { type: "stderr"; line: string }
  | { type: "exit"; run_id: string; code: number | null; finished_at: string }
  | { type: "rejected"; gate: string; reason: string }
  /** Emitted when a run's output was parsed into structured state — how many hosts /
   *  services / endpoints / credentials / findings it added. Purely informational; the
   *  panel uses it to know a refresh is worth doing. */
  | {
      type: "state";
      run_id: string;
      added: {
        hosts: number;
        services: number;
        endpoints: number;
        credentials: number;
        findings: number;
      };
    }
  /** ENGAGEMENT only — recon-driven expansion. Hosts this run's output revealed, split by the
   *  authorized scope: `in_scope` joined the live allowed set, `out_of_scope` is surfaced
   *  read-only and never targetable. Adding a host approves nothing: every command against one
   *  still needs its own individual approval. */
  | {
      type: "discovered";
      run_id: string;
      in_scope: string[];
      out_of_scope: string[];
      truncated: boolean;
    }
  | { type: "error"; reason: string };

export type ExecPayload = {
  command: string;
  args: string[];
  approved: boolean;
  /** Explicit second confirmation for a command carrying dangerous flags. The executor's
   *  danger gate refuses (403) unless this is true when dangerous flags are present. */
  dangerous_ack?: boolean;
  session_id?: string | null;
  step_id?: string | null;
  /** When set to an ACTIVE engagement id, run in REAL-TARGET engagement mode (Wall-A
   *  sandbox, no isolation floor) against that engagement's named target. Omit for lab. */
  engagement_id?: string | null;
  /** When set to a saved Windows-target profile id, run the command as PowerShell ON that
   *  Windows box over WinRM (a new transport behind the SAME gates). The target is the
   *  profile's host, hardcoded server-side. Omit for a Linux (docker) run. */
  windows_profile_id?: string | null;
  /** How long this ONE command may run before it is killed. Omit for the 180s default;
   *  above the 3600s ceiling it is CLAMPED, not refused. A full port sweep, a big ffuf or
   *  a nuclei run does not finish in 180s. Not a safety control — every gate still applies. */
  timeout_seconds?: number | null;
  /**
   * Throttle this run to roughly this many requests per second, by adding the tool's OWN
   * rate/delay flag. ENGAGEMENT MODE ONLY — a lab run ignores it and says so in the start
   * event's notes, as does a tool with no known throttle flag or one that already carries
   * its own rate. Not a safety control: a paced command is quieter, not safer, and every
   * gate still applies to the rewritten command line.
   */
  pace?: number | null;
  /** Run detached: returns a run_id immediately and the command keeps going server-side,
   *  with output replayable from /cockpit/runs/{id}/stream. Gates are identical — a
   *  backgrounded run is still individually approved BEFORE it starts. */
  background?: boolean;
};

/** 202 response to a backgrounded POST /cockpit/exec — the run is going, detached. */
export type ExecAccepted = {
  run_id: string;
  background: true;
  command: string;
  args: string[];
  target: string;
  mode: "lab" | "engagement";
  started_at: string;
  timeout_seconds: number;
  workdir: string | null;
  stream_url: string;
};

// ---- Engagement mode (REAL targets — no isolation floor; Wall-A + approve-each) ---- //

/** An entered engagement — the deliberate, human-authorized real-target mode record. */
export type EngagementRecord = {
  engagement_id: string;
  target: string;
  authorization: string;
  active: boolean;
  entered_at: string;
  exited_at: string | null;
  session_id: string | null;
  /** The authorized PROGRAM SCOPE, exactly as the operator wrote it. */
  scope: string;
  /** IN-SCOPE patterns (exact hosts, *.wildcards, CIDRs). */
  scope_include: string[];
  /** Exclusions — these always beat a matching include. */
  scope_exclude: string[];
  /** Addresses the scope's exact hosts resolved to at entry. */
  scope_ips: string[];
  /** LIVE allowed set: the scope's hosts + every in-scope host recon has revealed. */
  allowed_hosts: string[];
  /** Hosts recon revealed that the scope covers (auto-added to the allowed set). */
  discovered_in_scope: string[];
  /** Hosts recon revealed that the scope does NOT cover — read-only, never targetable. */
  discovered_out_of_scope: string[];
  /**
   * NAMES of the WAF-bypass headers this engagement holds. The VALUES are credentials and are
   * deliberately absent — this record is returned to the browser, joined into the LLM proposer
   * context and rendered into reports. There is no field here for a value to leak from.
   */
  bypass_header_names: string[];
};

/** Active engagement(s) + sandbox availability (GET /cockpit/engagement). Drives the UI mode
 *  indicator, which must ALWAYS show whether lab or a real-target engagement is active. The
 *  engagement sandbox is fully open (Wall A down): `ready` is just availability. */
export type EngagementStatus = {
  active: EngagementRecord[];
  sandbox: string;
  up: boolean;
  /** Always true — the engagement sandbox is fully open (no Wall A / isolation to verify). */
  open: boolean;
  ready: boolean;
  detail: string;
};

export const getEngagementStatus = (signal?: AbortSignal) =>
  getJSON<EngagementStatus>("/cockpit/engagement", signal);

/** DELIBERATELY enter real-target engagement mode. `target` is the real authorized host/URL;
 *  `authorization` is the operator's acknowledgement they own/are authorized to test it;
 *  `scope` is the authorized PROGRAM SCOPE (comma/space-separated exact hosts, *.wildcards,
 *  CIDRs, plus !exclusions) — omit it to scope the engagement to the target alone. The scope
 *  is resolved server-side and fails closed (422) if it is empty, malformed, unresolvable, or
 *  does not contain the named target. */
export const enterEngagement = (
  target: string,
  authorization: string,
  sessionId?: string | null,
  signal?: AbortSignal,
  scope?: string | null
) =>
  postJSON<EngagementRecord>(
    "/cockpit/engagement/enter",
    {
      target,
      authorization,
      session_id: sessionId ?? null,
      scope: scope?.trim() ? scope.trim() : null,
    },
    signal
  );

/** Leave engagement mode for this id — no further engagement-mode runs against it. */
export const exitEngagement = (engagementId: string, signal?: AbortSignal) =>
  postJSON<{ engagement_id: string; exited: boolean }>(
    `/cockpit/engagement/${encodeURIComponent(engagementId)}/exit`,
    {},
    signal
  );

export const getCockpitAllowlist = (signal?: AbortSignal) =>
  getJSON<CockpitAllowlist>("/cockpit/allowlist", signal);

export const getCockpitStatus = (signal?: AbortSignal) =>
  getJSON<CockpitStatus>("/cockpit/status", signal);

export const getCockpitRun = (runId: string, signal?: AbortSignal) =>
  getJSON<CockpitRun>(`/cockpit/runs/${encodeURIComponent(runId)}`, signal);

/** Every recorded run attached to an engagement, in execution order. This is
 *  how a cockpit run surfaces as a recorded engagement step. */
export const listCockpitRuns = (sessionId: string, signal?: AbortSignal) =>
  getJSON<CockpitRun[]>(
    `/cockpit/runs?session_id=${encodeURIComponent(sessionId)}`,
    signal
  );

/**
 * Run one approved command and stream its output events.
 *
 * A safety-gate failure comes back as HTTP 403 (nothing ran) — surfaced as an
 * ApiError whose message names the gate + reason. Otherwise each SSE `data:`
 * event is parsed and handed to `onEvent` as it arrives; the promise resolves
 * when the stream ends.
 */
export async function execCockpitStream(
  payload: ExecPayload,
  onEvent: (ev: ExecEvent) => void,
  signal?: AbortSignal
): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/cockpit/exec`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify(payload),
      signal,
    });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }

  if (!res.ok || !res.body) {
    // 403 gate rejection carries { detail: { gate, reason } }.
    let msg = `Request failed (${res.status}).`;
    try {
      const body = (await res.json()) as { detail?: { gate?: string; reason?: string } | string };
      if (body?.detail && typeof body.detail === "object") {
        msg = `[${body.detail.gate}] ${body.detail.reason}`;
      } else if (typeof body?.detail === "string") {
        msg = body.detail;
      }
    } catch {
      /* keep fallback */
    }
    throw new ApiError(res.status, msg);
  }

  await pumpExecEvents(res.body, onEvent);
}

/** Drain an SSE body, handing each parsed `data:` payload to `onEvent`. Shared by the
 *  foreground stream and the background reattach so both parse frames identically. */
async function pumpExecEvents(
  body: ReadableStream<Uint8Array>,
  onEvent: (ev: ExecEvent) => void
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let sep: number;
    while ((sep = buf.indexOf("\n\n")) >= 0) {
      const frame = buf.slice(0, sep);
      buf = buf.slice(sep + 2);
      const dataLine = frame.split("\n").find((l) => l.startsWith("data:"));
      if (!dataLine) continue;
      try {
        onEvent(JSON.parse(dataLine.slice(5).trim()) as ExecEvent);
      } catch {
        /* ignore a malformed frame */
      }
    }
  }
}

/**
 * Start a command DETACHED and return as soon as it is running.
 *
 * Same gates, same approval — `background` only changes when output is read. A safety-gate
 * failure is still a 403 with nothing run. Follow the output with `attachCockpitStream`.
 */
export async function execCockpitBackground(
  payload: ExecPayload,
  signal?: AbortSignal
): Promise<ExecAccepted> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/cockpit/exec`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, background: true }),
      signal,
    });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status}).`;
    try {
      const body = (await res.json()) as { detail?: { gate?: string; reason?: string } | string };
      if (body?.detail && typeof body.detail === "object") {
        msg = `[${body.detail.gate}] ${body.detail.reason}`;
      } else if (typeof body?.detail === "string") {
        msg = body.detail;
      }
    } catch {
      /* keep fallback */
    }
    throw new ApiError(res.status, msg);
  }
  return (await res.json()) as ExecAccepted;
}

/**
 * Attach to a backgrounded run: replays everything it has already produced, then follows
 * it live. Safe to call repeatedly — each attach starts from the beginning of the buffer,
 * which is what makes reconnecting after a reload lossless. Read-only: starts nothing.
 */
export async function attachCockpitStream(
  runId: string,
  onEvent: (ev: ExecEvent) => void,
  signal?: AbortSignal
): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/cockpit/runs/${encodeURIComponent(runId)}/stream`, {
      headers: { Accept: "text/event-stream" },
      signal,
    });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok || !res.body) {
    throw new ApiError(res.status, `Could not attach to run ${runId} (${res.status}).`);
  }
  await pumpExecEvents(res.body, onEvent);
}

// --- the orchestrator loop: propose the NEXT command (no execution) -------------

/** One proposed next command from the guided loop. `gate_ok` is the advisory
 *  pre-check against the M1 allowlist + target-lock; a false proposal is shown
 *  flagged and can't be approved (the executor would reject it anyway). */
export type LoopProposal = {
  command: string;
  args: string[];
  rationale: string;
  step_id: string | null;
  gate_ok: boolean;
  gate_reason: string;
  /** Escalation flags DETECTED in this proposal (never blocked). When non-empty the
   *  approval surface shows them RED and APPROVE needs an explicit second confirm. */
  dangerous_flags: string[];
};

export type LoopProposeOut = {
  done: boolean;
  proposal: LoopProposal | null;
  reason: string | null;
};

/**
 * Ask the agent for the next single recon command for a session's loop. This does
 * NOT execute — the returned proposal awaits human approval, after which it runs
 * through the M1 executor (execCockpitStream). `avoid` lists command lines the
 * operator skipped so the agent proposes something different.
 */
/** Ask the loop for the next draft command. With `engagementId` the agent drafts against that
 *  engagement's REAL target + authorized program scope (incl. recon-discovered in-scope hosts)
 *  instead of the isolated lab; an unknown/exited id is refused (409), never downgraded to lab.
 *  The result is a DRAFT either way — nothing runs until the operator approves that command. */
export const loopPropose = (
  sessionId: string,
  avoid: string[] = [],
  signal?: AbortSignal,
  engagementId?: string | null
) =>
  postJSON<LoopProposeOut>(
    `/sessions/${encodeURIComponent(sessionId)}/loop/propose`,
    { avoid, engagement_id: engagementId ?? null },
    signal
  );

// --- :exploits — the version-keyed CVE -> exploit lookup ------------------------

/** Index size + readiness (GET /exploits/stats). `ready: false` = not built yet. */
export type ExploitStats = {
  ready: boolean;
  entries?: number;
  with_cve?: number;
  with_version?: number;
  distinct_cves?: number;
  source?: string;
  exploit_root?: string;
};

/** One exploit-db hit — `version_match` and `why` are the confidence, and the point. */
export type ExploitHit = {
  id: string;
  title: string;
  product: string;
  version_kind: string;
  versions: string[];
  cves: string[];
  type: string;
  platform: string;
  port: string;
  author: string;
  date: string;
  verified: boolean;
  /** Where the exploit body already sits INSIDE the sandbox. */
  path: string;
  url: string;
  score: number;
  /** exact | in-range | line | product-only | different */
  version_match: string;
  why: string;
};

export const getExploitStats = (signal?: AbortSignal) =>
  getJSON<ExploitStats>("/exploits/stats", signal);

/** Free-text: a CVE id, a product, or the `product version` straight off a banner. */
export const searchExploits = (q: string, limit = 40, signal?: AbortSignal) =>
  getJSON<ExploitHit[]>(
    `/exploits/search?q=${encodeURIComponent(q)}&limit=${limit}`,
    signal
  );

/** The structured form a discovered service maps onto (nmap product + version). */
export const exploitsForService = (
  product: string,
  version?: string | null,
  signal?: AbortSignal
) =>
  getJSON<ExploitHit[]>(
    `/exploits/service?product=${encodeURIComponent(product)}` +
      (version ? `&version=${encodeURIComponent(version)}` : ""),
    signal
  );

/** Every exploit naming this CVE — an EXACT keyed lookup, no ranking involved.
 *  Distinct from `searchExploits("CVE-…")`, which ranks and can surface near-misses:
 *  when you already hold the CVE id, the table answer is the one you want. */
export const exploitsForCve = (cve: string, signal?: AbortSignal) =>
  getJSON<ExploitHit[]>(`/exploits/cve/${encodeURIComponent(cve.trim())}`, signal);

/** One CVE affecting a product, and how many catalogued exploits name it. */
export type CveRow = {
  cve: string;
  exploits: number;
  /** How the product/version matched — same vocabulary as ExploitHit.version_match. */
  best_match: string;
};

/** The distinct CVEs affecting a product/version, most-exploited first.
 *  Answers "what is this service vulnerable to", which the exploit list alone does not:
 *  twelve exploits can all name one CVE, and one CVE can have none. */
export const cvesForService = (
  product: string,
  version?: string | null,
  signal?: AbortSignal
) =>
  getJSON<CveRow[]>(
    `/exploits/cves?product=${encodeURIComponent(product)}` +
      (version ? `&version=${encodeURIComponent(version)}` : ""),
    signal
  );

// --- :terminal — raw PTY into the SAME open sandbox (a second surface, not a swap) ---

/** Availability of the raw-terminal surface (GET /cockpit/terminal/status).
 *  `isolated` is always false, exactly like :kali — this is the full-reach box. */
export type TerminalStatus = {
  container: string;
  shell: string;
  isolated: boolean;
  up: boolean;
  ready: boolean;
  live: number;
  max_live: number;
  detail: string;
};

export const getTerminalStatus = (signal?: AbortSignal) =>
  getJSON<TerminalStatus>("/cockpit/terminal/status", signal);

/**
 * The WebSocket URL for one raw PTY session.
 *
 * The geometry rides on the query string so the pty is created at the browser's real size
 * — otherwise the first full-screen app would draw at the 80x24 default and only correct
 * itself on the first resize. Nothing else is sent: no container, no shell, no command.
 */
export function terminalSocketUrl(
  cols: number,
  rows: number,
  sessionId?: string | null
): string {
  const base = API_URL.replace(/^http/, "ws");
  const qs = new URLSearchParams({ cols: String(cols), rows: String(rows) });
  if (sessionId) qs.set("session_id", sessionId);
  return `${base}/cockpit/terminal/ws?${qs.toString()}`;
}

// --- :kali — human-only arbitrary shell into the isolated sandbox ---------------

/** Availability of the :kali OPEN sandbox (GET /cockpit/kali/status). Note: `isolated`
 *  is always false — :kali intentionally has full network reach. */
export type KaliStatus = {
  container: string;
  isolated: boolean;
  up: boolean;
  ready: boolean;
  detail: string;
};

export const getKaliStatus = (signal?: AbortSignal) =>
  getJSON<KaliStatus>("/cockpit/kali/status", signal);

/** The captured result of one :kali shell run (POST /cockpit/kali). */
export type KaliResult = {
  run_id: string;
  command: string;
  container: string;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  started_at: string;
  finished_at: string;
  timed_out: boolean;
  truncated: boolean;
  session_id: string | null;
};

/**
 * Run ONE arbitrary shell command inside the isolated sandbox.
 *
 * The container is hardcoded server-side — this payload carries no target. A refusal
 * (sandbox not provably isolated) comes back as HTTP 409 with { detail: { gate, reason } };
 * it is surfaced as an ApiError naming the gate + reason, and nothing ran.
 */
export async function runKali(
  payload: {
    command: string;
    session_id?: string | null;
    /** Seconds before the command is killed. Omit for the 180s default; clamped at 3600s.
     *  This used to be a hardcoded 60s with no override, which made :kali useless for the
     *  long-running work a full shell is actually for. */
    timeout_seconds?: number | null;
  },
  signal?: AbortSignal
): Promise<KaliResult> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/cockpit/kali`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
      signal,
    });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status}).`;
    try {
      const body = (await res.json()) as {
        detail?: { gate?: string; reason?: string } | string;
      };
      if (body?.detail && typeof body.detail === "object") {
        msg = `[${body.detail.gate}] ${body.detail.reason}`;
      } else if (typeof body?.detail === "string") {
        msg = body.detail;
      }
    } catch {
      /* keep fallback */
    }
    throw new ApiError(res.status, msg);
  }
  return (await res.json()) as KaliResult;
}

// --- Persistent :kali shell (step 13 — cd/env/jobs persist across commands) ------- //

/** A live persistent :kali shell. Same containment as one-shot :kali; state persists. */
export type KaliShellInfo = {
  sid: string;
  container: string;
  state: "active" | "closed";
  started_at: string;
  last_active: string;
  command_count: number;
  session_id: string | null;
};

/** The result of ONE command run in a persistent shell. */
export type KaliCommandResult = {
  sid: string;
  run_id: string;
  command: string;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  started_at: string;
  finished_at: string;
  timed_out: boolean;
  truncated: boolean;
  shell_closed: boolean;
};

async function kaliShellFetch<T>(path: string, init: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, init);
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status}).`;
    try {
      const body = (await res.json()) as { detail?: { reason?: string } | string };
      if (body?.detail && typeof body.detail === "object") msg = body.detail.reason ?? msg;
      else if (typeof body?.detail === "string") msg = body.detail;
    } catch {
      /* keep fallback */
    }
    throw new ApiError(res.status, msg);
  }
  return (await res.json()) as T;
}

/** Open a persistent shell. 409 if the open sandbox is not running. */
export const startKaliShell = (sessionId?: string | null, signal?: AbortSignal) =>
  kaliShellFetch<KaliShellInfo>("/cockpit/kali/shell", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: sessionId ?? null }),
    signal,
  });

/** Run one command in a persistent shell — state persists to the next call. */
export const runInKaliShell = (
  sid: string,
  command: string,
  timeoutSeconds?: number | null,
  signal?: AbortSignal
) =>
  kaliShellFetch<KaliCommandResult>(`/cockpit/kali/shell/${encodeURIComponent(sid)}/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command, timeout_seconds: timeoutSeconds ?? null }),
    signal,
  });

/** Close a persistent shell (EOF stdin, then kill). */
export const closeKaliShell = (sid: string, signal?: AbortSignal) =>
  kaliShellFetch<KaliShellInfo>(`/cockpit/kali/shell/${encodeURIComponent(sid)}`, {
    method: "DELETE",
    signal,
  });

// --- HTTP repeater — compose / send / replay / diff (see backend/cockpit/repeater.py) ---
//
// SAME containment as :kali (hardcoded open container, HUMAN-ONLY, audited) plus a scope
// check :kali does not have. It sends argv-only curl from inside the sandbox — never from
// this browser or the backend host. A human clicking Send IS the approval; there is no
// per-send gate. An out-of-scope host (for a named engagement) comes back as 403.

export type RepeaterHeader = { name: string; value: string };

export type RepeaterRequest = {
  method: string;
  url: string;
  headers: RepeaterHeader[];
  body: string;
  follow_redirects: boolean;
  insecure: boolean;
  http2: boolean;
  timeout_seconds?: number | null;
  engagement_id?: string | null;
  session_id?: string | null;
  /**
   * THE COOKIE JAR (build #19 item 2). ON by default — the thing it fixes, every authenticated
   * flow breaking on the SECOND request, is the common case. `false` sends with NO session
   * WITHOUT emptying the jar: testing what an unauthenticated caller sees is a real test and it
   * must not cost you the session you established by hand.
   */
  use_cookie_jar?: boolean;
  /**
   * PAYLOAD SHAPING (build #18 item 4) — transforms applied to every `[[…]]` span in the URL
   * and body, in order. An OPTION, NOT A GATE: no confirm, no acknowledgement, no refusal if
   * unset. With no shapes the markers are simply stripped, which is what makes shaped-versus-
   * unshaped a one-variable comparison rather than two different requests.
   *
   * It lives here and not on the scanner because ZAP's API exposes no arbitrary payload
   * transform — a knob there would have been a switch with nothing different on the wire.
   */
  shapes?: string[];
};

export type RepeaterResponse = {
  status: number | null;
  http_version: string;
  reason: string;
  headers: RepeaterHeader[];
  body: string;
  body_truncated: boolean;
  size_bytes: number;
  time_ms: number;
  final_url: string;
  error: string;
};

export type RepeaterExchange = {
  id: string;
  run_id: string;
  request: RepeaterRequest;
  response: RepeaterResponse;
  sent_at: string;
  container: string;
  session_id: string | null;
  /**
   * THE REQUEST AS SHAPED — what actually went on the wire. `request` above is what was
   * composed, markers and all. A shaped request that comes back 200 is only evidence if you can
   * see the bytes that produced it.
   */
  sent_url: string;
  sent_body: string;
  shapes_applied: string[];
  /** Shapes that did nothing, and why. WARN AND CONTINUE — the request was still sent. */
  shape_warnings: string[];
  /**
   * THE COOKIE JAR'S DISCLOSURE (build #19 item 2). A `Cookie:` header you did not type has to
   * explain itself, or the jar is state that silently changes a request.
   *
   * NOTE THE ABSENCE OF A VALUE FIELD on CookieAttachment. That is not an oversight — this
   * object is a JSON body anything downstream may log, and never handing a session token over
   * cannot regress, while redacting it afterwards depends on a redactor being correct forever.
   */
  cookies_attached: CookieAttachment[];
  cookies_stored: CookieAttachment[];
  cookie_warnings: string[];
  cookie_jar_used: boolean;
};

/** One cookie, described. NAME, DOMAIN, PATH and PROVENANCE — deliberately no value. */
export type CookieAttachment = {
  name: string;
  domain: string;
  path: string;
  set_by_url: string;
  set_at: string;
};

const jarQS = (sessionId: string | null) =>
  sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : "";

/** What is in the jar. Value-free by construction — the route has no value to give. */
export const repeaterCookies = (sessionId: string | null, signal?: AbortSignal) =>
  getJSON<CookieAttachment[]>(`/cockpit/repeater/cookies${jarQS(sessionId)}`, signal);

/** Empty the jar. Ungated — clearing state removes capability. */
export const clearRepeaterCookies = (sessionId: string | null, signal?: AbortSignal) =>
  delJSON<{ session_id: string | null; cleared: number }>(
    `/cockpit/repeater/cookies${jarQS(sessionId)}`,
    signal
  );

/** The shaping vocabulary, from the backend so the UI carries no second copy of the list. */
export type ShapeVocabulary = {
  open: string;
  close: string;
  shapes: Record<string, string>;
};

export const getRepeaterShapes = (signal?: AbortSignal) =>
  getJSON<ShapeVocabulary>("/cockpit/repeater/shapes", signal);

/**
 * The request AS IT WOULD GO ON THE WIRE, without sending it. Calls the same function the send
 * path uses, so what is previewed is what is transmitted — one derivation, not two.
 */
export const repeaterPreview = (req: RepeaterRequest, signal?: AbortSignal) =>
  postJSON<{ url: string; body: string; shapes_applied: string[]; warnings: string[] }>(
    "/cockpit/repeater/preview",
    req,
    signal
  );

export type RepeaterStatus = {
  container: string;
  up: boolean;
  ready: boolean;
  detail: string;
};

export const getRepeaterStatus = (signal?: AbortSignal) =>
  getJSON<RepeaterStatus>("/cockpit/repeater/status", signal);

/** Send one composed request. A 403 (out of scope) or 409 (sandbox down) surfaces as an
 *  ApiError naming the gate + reason — nothing was sent. */
export const repeaterSend = (req: RepeaterRequest, signal?: AbortSignal) =>
  postJSON<RepeaterExchange>("/cockpit/repeater/send", req, signal);

export const getRepeaterHistory = (
  sessionId?: string | null,
  signal?: AbortSignal
) =>
  getJSON<RepeaterExchange[]>(
    `/cockpit/repeater/history${sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : ""}`,
    signal
  );

// --- Pivot / tunnel routing — chisel / ligolo-ng (see backend/cockpit/tunnels.py) ---
//
// HUMAN-ONLY listener lifecycle (start/stop). Routing + rewrite are pure — routeCommand
// returns the proxychains-wrapped command the HUMAN approves (the prefix is VISIBLE, applied
// BEFORE approval). A tunnel's subnet enters engagement scope ONLY via addPivotSubnet, by hand.

export type Tunnel = {
  id: string;
  kind: string;
  /** 'socks' (proxychains) or 'interface' (ip route via ligolo tun). */
  routing: string;
  lhost: string;
  listen_port: number;
  socks_port: number | null;
  subnets: string[];
  status: string;
  /** The one-liner to paste on the compromised host. */
  agent_command: string;
  setup_note: string;
  /** What was OBSERVED about the process and its port — the evidence behind `status`. */
  liveness: string;
  started_at: string;
  engagement_id: string | null;
};

export type TunnelsStatus = {
  container: string;
  up: boolean;
  live_tunnels: number;
  detail: string;
};

export const getTunnelsStatus = (signal?: AbortSignal) =>
  getJSON<TunnelsStatus>("/cockpit/tunnels/status", signal);

export const listTunnels = (signal?: AbortSignal) =>
  getJSON<Tunnel[]>("/cockpit/tunnels", signal);

export const startTunnel = (
  body: {
    kind: string;
    lhost: string;
    listen_port?: number | null;
    subnets: string[];
    engagement_id?: string | null;
    // A pivot listener is a route into a real network, so starting it clears the same gates as
    // any execution: an explicit approval and the danger red-confirm. Both default false on the
    // backend, so omitting them is a refusal, never a silent grant.
    approved?: boolean;
    dangerous_ack?: boolean;
  },
  signal?: AbortSignal
) => postJSON<Tunnel>("/cockpit/tunnels", body, signal);

export const stopTunnel = (tid: string, signal?: AbortSignal) =>
  fetch(`${API_URL}/cockpit/tunnels/${encodeURIComponent(tid)}`, {
    method: "DELETE",
    signal,
  }).then((r) => r.json() as Promise<Tunnel>);

/* -------------------------------------------------------------------------- */
/* the recording proxy (build #14 part 2)                                     */
/* -------------------------------------------------------------------------- */
export type Proxy = {
  id: string;
  container: string;
  port: number;
  /** starting | listening | down — OBSERVED after the settle window, never assumed. */
  status: string;
  /** What was actually seen about the process and its port. The evidence behind `status`. */
  liveness: string;
  captured: number;
  started_at: string;
  engagement_id: string | null;
  /** The address it bound INSIDE the container — 127.0.0.1 unless it was published. */
  bind_host: string;
  /**
   * Bound wide inside its container so a published host port can reach it. This does NOT mean
   * a host port exists — publishing one is the exposure profile's separate, explicit job.
   */
  published: boolean;
  /** Whether the API requires a key. NEVER the key itself — that value never leaves the backend. */
  api_key_enforced: boolean;
  /**
   * NAMES of the WAF-bypass headers ZAP is actually holding, READ BACK from its replacer rules
   * rather than echoed from what was sent. The VALUES are credentials and never leave the
   * backend — there is no field here for one, which is the version of that property a future
   * edit cannot quietly undo.
   */
  bypass_headers: string[];
};

export type ProxyStatus = {
  lab_sandbox: string;
  lab_running: boolean;
  engage_sandbox: string;
  engage_running: boolean;
  live: number;
  default_port: number;
};

export type CapturedHeader = { name: string; value: string };

/** One recorded request/response pair. Field names match the repeater's on purpose. */
export type CapturedExchange = {
  id: string;
  request: { method: string; url: string; headers: CapturedHeader[]; body: string };
  response: {
    status: number | null;
    headers: CapturedHeader[];
    body: string;
    size_bytes: number;
    time_ms: number;
  };
  sent_at: string;
  container: string;
};

export const getProxyStatus = (signal?: AbortSignal) =>
  getJSON<ProxyStatus>("/cockpit/proxy/status", signal);

export const listProxies = (signal?: AbortSignal) =>
  getJSON<Proxy[]>("/cockpit/proxy", signal);

export const startProxy = (
  body: {
    port?: number;
    engagement_id?: string | null;
    /**
     * Bind the daemon wide INSIDE its container so a published host port can reach it — what
     * lets a real browser on this machine use the proxy. ENGAGEMENT-ONLY (409 at gate
     * `publish` in lab mode: that network is `internal: true`, so a published port has no
     * route). It publishes nothing on its own; the host port is a separate exposure profile.
     */
    publish?: boolean;
    // A recording proxy holds full request bodies — credentials and session tokens in
    // cleartext — so starting it clears an explicit approval AND the danger red-confirm.
    // Both default false on the backend, so omitting them is a refusal, never a silent grant.
    approved?: boolean;
    dangerous_ack?: boolean;
  },
  signal?: AbortSignal
) => postJSON<Proxy>("/cockpit/proxy", body, signal);

export const stopProxy = (pid: string, signal?: AbortSignal) =>
  fetch(`${API_URL}/cockpit/proxy/${encodeURIComponent(pid)}`, {
    method: "DELETE",
    signal,
  }).then((r) => r.json() as Promise<Proxy>);

/**
 * One window of captured traffic, WITH THE ARITHMETIC THAT MAKES IT READABLE.
 *
 * It is an object rather than a bare list on purpose. A message the backend's parser cannot
 * read used to vanish from the array with nothing anywhere saying it had existed, so a window
 * of 200 exchanges of which 50 were unparseable arrived as 150 and read as less traffic. Not a
 * confident zero — a confident UNDERCOUNT, which is harder to notice because it looks plausible.
 */
export type HistoryPage = {
  exchanges: CapturedExchange[];
  /** Messages ZAP holds in total, from its own counter. */
  total: number;
  /** Absolute offset of the first row in this window. */
  window_start: number;
  /** Rows you can actually read. */
  returned: number;
  /** Rows ZAP returned that could NOT be parsed. Non-zero means this list is INCOMPLETE. */
  dropped: number;
  /** False means the API did not answer — a different fact from "nothing was captured". */
  read_ok: boolean;
};

/** Captured exchanges. READ-ONLY; bodies come back RAW (redaction applies only in reports). */
export const proxyHistory = (
  container: string,
  port: number,
  count = 50,
  signal?: AbortSignal
) =>
  getJSON<HistoryPage>(
    `/cockpit/proxy/history?container=${encodeURIComponent(container)}&port=${port}&count=${count}`,
    signal
  );

/* -------------------------------------------------------------------------- */
/* HISTORY FILTERING (build #19 item 3)                                        */
/*                                                                             */
/* THE COUNTS ARE THE FEATURE. An empty `exchanges` is FOUR different facts —   */
/* ZAP holds nothing, nothing matched, the read failed, or the scan stopped     */
/* before reaching the rows that would have matched. The screen must be able to */
/* tell them apart, so every count comes back and `truncated` is never silent.  */
/* -------------------------------------------------------------------------- */
export type HistoryFilter = {
  host?: string;
  method?: string[];
  status?: number[];
  url_contains?: string;
  has_param?: boolean | null;
  content_type?: string;
  in_scope_of?: string;
};

export type FilteredHistory = {
  exchanges: CapturedExchange[];
  total: number;
  /** Messages actually READ and tested against the filter. */
  scanned: number;
  /** Messages that matched, BEFORE `limit` was applied. */
  matched: number;
  returned: number;
  /** Rows that could not be parsed, so they were never tested at all. */
  dropped: number;
  read_ok: boolean;
  /** Older messages exist that were never examined — a match may be missing. */
  truncated: boolean;
  scope_note: string;
};

export const filterProxyHistory = (
  container: string,
  port: number,
  filter: HistoryFilter,
  limit = 200,
  signal?: AbortSignal
) =>
  postJSON<FilteredHistory>(
    `/cockpit/proxy/history/filter?container=${encodeURIComponent(container)}&port=${port}&limit=${limit}`,
    filter,
    signal
  );

/* -------------------------------------------------------------------------- */
/* INTERCEPTION (build #19 item 4)                                             */
/*                                                                             */
/* UNGATED IN BOTH DIRECTIONS. A request is held, a HUMAN reads it, a HUMAN     */
/* edits it, a HUMAN forwards it — the press IS the approval. And while         */
/* breaking is on the operator's own BROWSER IS FROZEN, so a gate that could    */
/* refuse to turn it off would look exactly like the target having gone down.   */
/* -------------------------------------------------------------------------- */
export type InterceptState = {
  container: string;
  port: number;
  /** ZAP's own `isBreakAll`. */
  breaking: boolean;
  /** Is a request actually WAITING? From httpMessage being non-empty — NEVER from
   *  `break_on_request`, which is a SETTING and reads true with nothing held. */
  held: boolean;
  /** The held request, raw. Empty when none. */
  message: string;
  break_on_request: boolean;
  break_on_response: boolean;
  /** False means the daemon did not answer — a DIFFERENT fact from "breaking is off". */
  read_ok: boolean;
  detail: string;
};

const interceptQS = (container: string, port: number) =>
  `container=${encodeURIComponent(container)}&port=${port}`;

export const getIntercept = (container: string, port: number, signal?: AbortSignal) =>
  getJSON<InterceptState>(`/cockpit/proxy/intercept?${interceptQS(container, port)}`, signal);

export const setIntercept = (
  container: string,
  port: number,
  on: boolean,
  signal?: AbortSignal
) =>
  postJSON<InterceptState>(
    `/cockpit/proxy/intercept?on=${on}&${interceptQS(container, port)}`,
    {},
    signal
  );

export const replaceIntercepted = (
  container: string,
  port: number,
  body: { http_header: string; http_body: string },
  signal?: AbortSignal
) =>
  postJSON<InterceptState>(
    `/cockpit/proxy/intercept/message?${interceptQS(container, port)}`,
    body,
    signal
  );

export const releaseIntercepted = (
  container: string,
  port: number,
  verb: "continue" | "drop" | "step",
  signal?: AbortSignal
) =>
  postJSON<InterceptState>(
    `/cockpit/proxy/intercept/release?verb=${verb}&${interceptQS(container, port)}`,
    {},
    signal
  );

/** DROP whatever is held and turn breaking OFF. The one-click way out. Never gated. */
export const panicIntercept = (container: string, port: number, signal?: AbortSignal) =>
  postJSON<{
    dropped_held_request: boolean;
    was_breaking: boolean;
    state: InterceptState;
    detail: string;
  }>(`/cockpit/proxy/intercept/panic?${interceptQS(container, port)}`, {}, signal);

/* -------------------------------------------------------------------------- */
/* THE INTRUDER (build #19 item 5)                                             */
/*                                                                             */
/* GATED EXACTLY LIKE THE SCANNER: the four gates, no new ones. HackPit refuses */
/* BATCHING ACROSS APPROVALS; it has never refused one approval that produces   */
/* many requests, because ffuf, nuclei and the ZAP active scanner are each      */
/* exactly that. The payload set and positions are IN the approved surface, the */
/* way crawl depth and duration are in the spider's.                            */
/* -------------------------------------------------------------------------- */
export type IntruderRequest = {
  url: string;
  method: string;
  headers: RepeaterHeader[];
  body: string;
  /** THE PAYLOAD SET, verbatim. Every entry goes into the approved surface. */
  payloads: string[];
  /** sniper = one position at a time; battering-ram = every position, same payload. */
  mode: string;
  shapes: string[];
  follow_redirects: boolean;
  insecure: boolean;
  delay_ms: number;
  engagement_id?: string | null;
  session_id?: string | null;
  use_cookie_jar: boolean;
  approved: boolean;
  /** Demanded by the GATE when the payloads warrant it, not by the form. */
  dangerous_ack: boolean;
};

export type IntruderResult = {
  index: number;
  /** The payload AS SENT — i.e. after shaping. */
  payload: string;
  position: number;
  url: string;
  status: number | null;
  size_bytes: number;
  time_ms: number;
  body_excerpt: string;
  error: string;
  /** The signal. A fuzzer's finding is the row that is not like the others. */
  differs_from_baseline: boolean;
};

export type IntruderJob = {
  id: string;
  state: string;
  request: IntruderRequest;
  container: string;
  started_at: string;
  finished_at: string;
  positions: number;
  planned: number;
  sent: number;
  results: IntruderResult[];
  baseline: IntruderResult | null;
  /** The payload set was longer than the ceiling. Reported, never silent. */
  capped: boolean;
  warnings: string[];
  /** Requests NOT sent because a payload moved the URL off-scope. */
  scope_refusals: number;
};

export type IntruderPreview = {
  argv: string[];
  positions: number;
  planned: number;
  sample: { position: number; payload: string; url: string }[];
  warnings: string[];
  capped: boolean;
  /** What the four gates WOULD say. `null` means nothing stands in the way. */
  gate: { gate: string; reason: string; dangerous_flags: string[] } | null;
};

export const getIntruderStatus = (signal?: AbortSignal) =>
  getJSON<{ container: string; up: boolean; ready: boolean; running: number; detail: string }>(
    "/cockpit/intruder/status",
    signal
  );

/** What would be sent AND whether the gate would refuse it — sending nothing. */
export const intruderPreview = (req: IntruderRequest, signal?: AbortSignal) =>
  postJSON<IntruderPreview>("/cockpit/intruder/preview", req, signal);

export const startIntruder = (req: IntruderRequest, signal?: AbortSignal) =>
  postJSON<IntruderJob>("/cockpit/intruder", req, signal);

export const listIntruderJobs = (signal?: AbortSignal) =>
  getJSON<IntruderJob[]>("/cockpit/intruder", signal);

export const getIntruderJob = (id: string, signal?: AbortSignal) =>
  getJSON<IntruderJob>(`/cockpit/intruder/${encodeURIComponent(id)}`, signal);

/** Stop an in-flight job. NOT GATED — the panic button, exactly like stopping a scan. */
export const stopIntruderJob = (id: string, signal?: AbortSignal) =>
  delJSON<IntruderJob>(`/cockpit/intruder/${encodeURIComponent(id)}`, signal);

/* -------------------------------------------------------------------------- */
/* THE WAF-BYPASS HEADER (build #18 item 1)                                    */
/*                                                                             */
/* THE VALUE IS A CREDENTIAL AND ONLY TRAVELS ONE WAY. `setBypassHeader` sends  */
/* it; every reader below answers with NAMES and with what ZAP holds. There is  */
/* no call in this file that returns a bypass header's value, because there is  */
/* no route that does.                                                          */
/* -------------------------------------------------------------------------- */

/** One replacer rule AS ZAP HOLDS IT. Note the absence of a `replacement` field. */
export type ReplacerRule = {
  description: string;
  match_type: string;
  /** For a REQ_HEADER rule this is the HEADER NAME — not a secret. */
  match_string: string;
  enabled: boolean;
  /** ZAP holds a non-empty value. The value itself is never reported. */
  replacement_set: boolean;
  /** HackPit installed it and HackPit will remove it. Rules added in ZAP's own UI are left alone. */
  hackpit_managed: boolean;
};

export const setBypassHeader = (
  body: { engagement_id: string; name: string; value: string },
  signal?: AbortSignal
) =>
  postJSON<{ engagement_id: string; bypass_header_names: string[] }>(
    "/cockpit/engagement/bypass-header",
    body,
    signal
  );

export const deleteBypassHeader = (engagementId: string, name: string, signal?: AbortSignal) =>
  fetch(
    `${API_URL}/cockpit/engagement/${encodeURIComponent(engagementId)}/bypass-header/${encodeURIComponent(name)}`,
    { method: "DELETE", signal }
  ).then((r) => r.json() as Promise<{ bypass_header_names: string[] }>);

/**
 * Make a running daemon hold exactly this engagement's bypass headers. An EMPTY engagement id
 * CLEARS — ZAP persists its configuration, so the failure worth preventing is a credential
 * surviving into a session it was not issued for.
 */
export const syncBypassHeaders = (
  container: string,
  port: number,
  engagementId: string,
  signal?: AbortSignal
) =>
  postJSON<{ installed: string[]; cleared: string[]; rules: ReplacerRule[] }>(
    `/cockpit/proxy/bypass-headers?container=${encodeURIComponent(container)}&port=${port}` +
      `&engagement_id=${encodeURIComponent(engagementId)}`,
    {},
    signal
  );

export const getReplacerRules = (container: string, port: number, signal?: AbortSignal) =>
  getJSON<ReplacerRule[]>(
    `/cockpit/proxy/bypass-headers?container=${encodeURIComponent(container)}&port=${port}`,
    signal
  );

/* -------------------------------------------------------------------------- */
/* IS IT CDN-FRONTED? (build #18 item 2) — PASSIVE LOOKUPS ONLY                */
/* -------------------------------------------------------------------------- */
export type FrontingEvidence = { source: string; detail: string; provider: string };

export type HostFronting = {
  host: string;
  /** fronted | not-fronted | unknown. `unknown` means the lookups failed — NOT "no CDN". */
  verdict: string;
  provider: string;
  cname_chain: string[];
  addresses: string[];
  server_header: string;
  asn: string;
  asn_org: string;
  evidence: FrontingEvidence[];
  /** Leads for a human. REPORTED, never added to any scope. */
  candidate_origins: string[];
  spf: string[];
  mx: string[];
  notes: string[];
};

export type FrontingSweep = {
  hosts: HostFronting[];
  fronted: string[];
  not_fronted: string[];
  unknown: string[];
  note: string;
};

export const analyseFronting = (
  body: { hosts?: string[]; engagement_id?: string; with_ct?: boolean },
  signal?: AbortSignal
) => postJSON<FrontingSweep>("/cockpit/fronting", body, signal);

/* -------------------------------------------------------------------------- */
/* the ACTIVE SCANNER over the same API (build #14 part 3)                     */
/*                                                                             */
/* Everything above this line RECORDS. Everything below ATTACKS. `startScan` is */
/* the only call in this file that sends attack traffic, and it is the only one */
/* that carries gate fields.                                                    */
/* -------------------------------------------------------------------------- */
export type Scan = {
  id: string;
  container: string;
  port: number;
  /** Blank for a scan this backend process did not start — ZAP does not record the aim. */
  target_url: string;
  recurse: boolean;
  /** ZAP's own word: RUNNING | PAUSED | FINISHED | STOPPED. Observed, never assumed. */
  state: string;
  progress: number;
  /** Attack requests actually sent. 376 against one endpoint in the measurement. */
  requests: number;
  alerts: number;
  started_at: string;
  engagement_id: string | null;
  /** The policy NAME requested. Blank for a scan this backend process did not start. */
  scan_policy: string;
  /** What ZAP actually HELD after the policy was applied — read back, never echoed. */
  policy_observed: ObservedPolicy | null;
  /**
   * NAMES of the WAF-bypass headers in force when this scan started. This is what makes a 403
   * share interpretable: "36 of 39 refused" means one thing with the program's bypass header on
   * and something else entirely without it.
   */
  bypass_headers: string[];
  /** The ZAP context this scan ran inside. Blank when none was configured — an ordinary scan. */
  context_name: string;
  /** 0 none | 2 context + session management | 3 form auth with re-login. */
  auth_tier: number;
};

/* -------------------------------------------------------------------------- */
/* SCAN POLICY (build #18 item 3) — fewer requests, and the ones that apply    */
/* -------------------------------------------------------------------------- */
export type ScanPolicy = {
  name: string;
  description: string;
  attack_strength: string;
  alert_threshold: string;
  /** ZAP plugin id -> WHY it is off. The reason is the part a human can disagree with. */
  disabled_scanners: Record<string, string>;
};

export type ObservedPolicy = {
  requested: string;
  attack_strength: string[];
  alert_threshold: string[];
  /** Requested off AND confirmed off by a read-back. */
  disabled_ids: number[];
  /** Requested off but NOT reported off — usually a plugin id this ZAP build does not have. */
  not_held: number[];
  /** 0 means THE READ FAILED, not that ZAP has no scan rules. */
  scanners_seen: number;
};

export const listScanPolicies = (signal?: AbortSignal) =>
  getJSON<ScanPolicy[]>("/cockpit/proxy/scan-policies", signal);

export const getScanPolicy = (
  container: string,
  port: number,
  requested = "",
  signal?: AbortSignal
) =>
  getJSON<ObservedPolicy>(
    `/cockpit/proxy/scan-policy?container=${encodeURIComponent(container)}&port=${port}` +
      `&requested=${encodeURIComponent(requested)}`,
    signal
  );

/* -------------------------------------------------------------------------- */
/* AUTHENTICATED SCANNING (build #18 items 6 and 7)                            */
/*                                                                             */
/* THERE IS NO PASSWORD FIELD ANYWHERE BELOW, and that is the property. Tier 2  */
/* needs no credential at all — the human already logged in through the proxy.  */
/* Tier 3 NAMES a stored vault credential and the backend resolves it.          */
/* -------------------------------------------------------------------------- */
export type AuthContext = {
  container: string;
  port: number;
  /** Empty means no context exists for this target. */
  context_id: string;
  context_name: string;
  included: string[];
  session_method: string;
  auth_method: string;
  logged_in_regex: string;
  logged_out_regex: string;
  user_id: string;
  /** The ACCOUNT NAME a scan runs as. A username is not a secret; the password has no field. */
  user_name: string;
  /** 0 nothing | 2 context + session management | 3 form auth with automatic re-login. */
  tier: number;
  /** Things that did not take. WARN AND CONTINUE — a weaker context is not a refusal. */
  warnings: string[];
};

export const setAuthContext = (
  body: {
    target_url: string;
    port?: number;
    engagement_id?: string | null;
    logged_in_regex?: string;
    logged_out_regex?: string;
    // Tier 3 only. All absent = Tier 2, which needs no credentials whatsoever.
    login_url?: string;
    login_body?: string;
    credential?: { session_id: string; kind: string; principal: string; domain?: string } | null;
  },
  signal?: AbortSignal
) => postJSON<AuthContext>("/cockpit/proxy/auth-context", body, signal);

export const getAuthContext = (
  container: string,
  port: number,
  targetUrl: string,
  signal?: AbortSignal
) =>
  getJSON<AuthContext>(
    `/cockpit/proxy/auth-context?container=${encodeURIComponent(container)}&port=${port}` +
      `&target_url=${encodeURIComponent(targetUrl)}`,
    signal
  );

export const clearAuthContexts = (container: string, port: number, signal?: AbortSignal) =>
  fetch(
    `${API_URL}/cockpit/proxy/auth-context?container=${encodeURIComponent(container)}&port=${port}`,
    { method: "DELETE", signal }
  ).then((r) => r.json() as Promise<{ removed: string[] }>);

export type ScanAlert = {
  id: string;
  name: string;
  /** High | Medium | Low | Informational — ZAP's vocabulary, not the Finding severity scale. */
  risk: string;
  confidence: string;
  url: string;
  method: string;
  param: string;
  evidence: string;
  attack: string;
  plugin_id: string;
  cwe_id: string;
  description: string;
  solution: string;
};

/**
 * Actively scan ONE URL the proxy already captured. SENDS REAL ATTACK TRAFFIC.
 *
 * Both gate fields default false on the backend, so omitting them is a refusal rather than a
 * silent grant. A 403 is a safety refusal naming the gate; a 409 is availability — including
 * `url_not_found`, which is ZAP declining to attack a URL it has never seen.
 */
export const startScan = (
  body: {
    target_url: string;
    port?: number;
    recurse?: boolean;
    /**
     * 'default' (every rule ZAP ships) or 'targeted-web' (the platform-locked rules off). An
     * UNKNOWN NAME FALLS BACK TO THE DEFAULT rather than refusing — a policy decides how many
     * requests to send, and nothing about it is a safety verdict. What actually ran comes back
     * on the Scan as `policy_observed`.
     */
    scan_policy?: string;
    engagement_id?: string | null;
    approved?: boolean;
    dangerous_ack?: boolean;
  },
  signal?: AbortSignal
) => postJSON<Scan>("/cockpit/proxy/scan", body, signal);

/** Every scan ZAP knows about, with live counts. Read-only — a progress bar polls this. */
export const listScans = (container: string, port: number, signal?: AbortSignal) =>
  getJSON<Scan[]>(
    `/cockpit/proxy/scan?container=${encodeURIComponent(container)}&port=${port}`,
    signal
  );

/** Stop an in-flight scan. NOT gated — this is the panic button while requests are in flight. */
export const stopScan = (
  scanId: string,
  container: string,
  port: number,
  signal?: AbortSignal
) =>
  fetch(
    `${API_URL}/cockpit/proxy/scan/${encodeURIComponent(scanId)}` +
      `?container=${encodeURIComponent(container)}&port=${port}`,
    { method: "DELETE", signal }
  ).then((r) => r.json() as Promise<Scan | null>);

/** Alerts ZAP holds. Includes PASSIVE alerts raised by proxied traffic, not just scan results. */
export const scanAlerts = (
  container: string,
  port: number,
  baseUrl = "",
  count = 100,
  signal?: AbortSignal
) =>
  getJSON<ScanAlert[]>(
    `/cockpit/proxy/alerts?container=${encodeURIComponent(container)}&port=${port}` +
      `&count=${count}${baseUrl ? `&base_url=${encodeURIComponent(baseUrl)}` : ""}`,
    signal
  );

/** Persist ZAP's alerts as Findings + Endpoints in engagement state. Writes; attacks nothing. */
export const ingestScanAlerts = (
  body: {
    session_id: string;
    container: string;
    port?: number;
    base_url?: string;
    count?: number;
  },
  signal?: AbortSignal
) =>
  postJSON<{
    alerts: number;
    /**
     * Alerts ZAP returned that could NOT be parsed and were therefore NOT ingested. A finding
     * that never parsed is a finding that never reaches a report, so it is stated next to the
     * count rather than left as a debug detail.
     */
    alerts_dropped: number;
    findings: number;
    endpoints: number;
  }>("/cockpit/proxy/alerts/ingest", body, signal);

/* -------------------------------------------------------------------------- */
/* the AJAX SPIDER — a browser-driven crawl (build #15 part 2)                 */
/*                                                                             */
/* Gated like the scanner, for a DIFFERENT reason. This sends NO injection      */
/* payloads. It drives a real browser that CLICKS things, and on a production   */
/* site that can submit a form, empty a basket, trigger email or place an       */
/* order. The confirm copy must say that, not borrow the scanner's words.       */
/* -------------------------------------------------------------------------- */
export type Spider = {
  container: string;
  port: number;
  target_url: string;
  /** ZAP's own word: running | stopped. OBSERVED on every poll, never assumed. */
  state: string;
  /** URLs the crawl has found so far. */
  results: number;
  /** Messages in ZAP's history — the evidence a browser actually ran. */
  captured: number;
  /**
   * READ BACK from ZAP, never echoed from what we set: `setOptionBrowserId` answers
   * `{"Result":"OK"}` for values it cannot use (it accepted `not-a-browser`), so the value we
   * sent proves nothing. An OK is not a result.
   */
  browser_id: string;
  max_depth: number;
  max_duration_minutes: number;
  started_at: string;
  engagement_id: string | null;
};

/**
 * Crawl a target with a real browser, through the session ZAP already holds.
 *
 * `max_depth` and `max_duration_minutes` are in the APPROVED COMMAND, not just in this request:
 * a crawler that decides its own bounds is a command that has stopped describing what runs.
 */
export const startSpider = (
  body: {
    target_url: string;
    port?: number;
    max_depth?: number;
    max_duration_minutes?: number;
    engagement_id?: string | null;
    approved?: boolean;
    dangerous_ack?: boolean;
  },
  signal?: AbortSignal
) => postJSON<Spider>("/cockpit/proxy/spider", body, signal);

/** What the crawl is doing right now. Read-only, ungated — a panel polls it. */
export const spiderStatus = (container: string, port: number, signal?: AbortSignal) =>
  getJSON<Spider>(
    `/cockpit/proxy/spider?container=${encodeURIComponent(container)}&port=${port}`,
    signal
  );

/** Stop an in-flight crawl. NOT gated — a browser is mid-click on a live site. */
export const stopSpider = (container: string, port: number, signal?: AbortSignal) =>
  fetch(
    `${API_URL}/cockpit/proxy/spider?container=${encodeURIComponent(container)}&port=${port}`,
    { method: "DELETE", signal }
  ).then((r) => r.json() as Promise<Spider>);

/** Resolve the tunnel for a host and get the rewritten command to APPROVE. Pure — nothing runs. */
export type RouteResult = {
  routed: boolean;
  command: string;
  args: string[];
  tunnel: Tunnel | null;
  note: string;
};

export const routeCommand = (
  body: { command: string; args: string[]; host: string },
  signal?: AbortSignal
) => postJSON<RouteResult>("/cockpit/tunnels/route", body, signal);

/** Widen an active engagement's scope to include a pivot subnet — an explicit human action. */
export const addPivotSubnet = (
  engagementId: string,
  cidr: string,
  signal?: AbortSignal
) =>
  postJSON<EngagementRecord>(
    "/cockpit/tunnels/scope",
    { engagement_id: engagementId, cidr },
    signal
  );

// --- Sliver C2 + DNS-tunnel obfuscation (see backend/cockpit/{sliver,obfuscation}.py) ---
//
// TWO FOOTINGS, never collapsed:
//   SERVER / LISTENER LIFECYCLE -> HUMAN-ONLY. Operator infrastructure on the operator's own
//     sandbox, with no target — clicking start IS the approval, so there is no gate.
//   IMPLANT GENERATION          -> a GATED command. previewImplant is PURE (argv + the gate
//     verdict, runs nothing); generateImplant runs the REAL executor gates and 403s naming the
//     gate. A payload generator trips the danger heuristic, so the red-confirm is required.
//
// The routes live on the backend's main.py (NOT the cockpit router) precisely because both
// surfaces are source-scan locked to "the module + the HTTP layer" — nothing autonomous may
// reach them. Nothing here delivers anything: an implant is generated and left on disk, and a
// tunnel's client one-liner is carried to the far side BY HAND.
//
// The DNS listener's pre-shared key NEVER crosses this boundary: the response model has no
// secret field and `client_command` arrives with the key MASKED (`***`). Substitute your own.

export type SliverStatus = {
  container: string;
  up: boolean;
  live_servers: number;
  max_live_servers: number;
  implants: number;
  detail: string;
};

export type SliverServer = {
  id: string;
  status: string;
  container: string;
  port: number;
  run_id: string;
  started_at: string;
  stopped_at: string | null;
  engagement_id: string | null;
  setup_note: string;
  /** What was OBSERVED about the process and its port — the evidence behind `status`. */
  liveness: string;
};

export type Implant = {
  id: string;
  run_id: string;
  status: string;
  os: string;
  arch: string;
  fmt: string;
  transport: string;
  /** The OPERATOR's callback address, verbatim — never the engagement target. */
  listener: string;
  target: string;
  mode: string;
  container: string;
  artifact_path: string;
  argv: string[];
  exit_code: number | null;
  detail: string;
  generated_at: string;
  engagement_id: string | null;
  session_id: string | null;
  step_id: string | null;
};

export type ImplantBody = {
  os: string;
  arch: string;
  fmt: string;
  transport: string;
  listener: string;
  target: string;
  engagement_id?: string | null;
  approved: boolean;
  dangerous_ack: boolean;
};

/** Pure preview: the exact argv a build WOULD run, plus which gate would refuse it. */
export type ImplantPreview = {
  argv: string[];
  listener: string;
  rejected: { reason: string; gate: string; dangerous_flags: string[] } | null;
};

export const getSliverStatus = (signal?: AbortSignal) =>
  getJSON<SliverStatus>("/api/sliver/status", signal);

export const listSliverServers = (signal?: AbortSignal) =>
  getJSON<SliverServer[]>("/api/sliver/servers", signal);

/**
 * Start the operator's own Sliver C2 server. GATED since build #7: `engagement_id` is REQUIRED
 * and both confirms must be explicit — the server used to be ungated on a precedent (the pivot
 * listener) that build #5's I2 finding overturned, and Sliver's config can persist listener jobs
 * that come up with the daemon. A 403 carries `{gate, reason}`; render the red-confirm from it
 * rather than retrying with `dangerous_ack` set behind the operator's back.
 */
export const startSliverServer = (
  body: {
    port?: number | null;
    engagement_id: string;
    approved: boolean;
    dangerous_ack: boolean;
  },
  signal?: AbortSignal
) => postJSON<SliverServer>("/api/sliver/servers", body, signal);

export const stopSliverServer = (sid: string, signal?: AbortSignal) =>
  fetch(`${API_URL}/api/sliver/servers/${encodeURIComponent(sid)}`, {
    method: "DELETE",
    signal,
  }).then((r) => r.json() as Promise<SliverServer>);

export const previewImplant = (body: ImplantBody, signal?: AbortSignal) =>
  postJSON<ImplantPreview>("/api/sliver/implants/preview", body, signal);

export const generateImplant = (body: ImplantBody, signal?: AbortSignal) =>
  postJSON<Implant>("/api/sliver/implants", body, signal);

export const listImplants = (signal?: AbortSignal) =>
  getJSON<Implant[]>("/api/sliver/implants", signal);

// --- the bespoke evasion engine (see backend/evasion/engine.py) ---
// GENERATE-ONLY: there is no deploy or execute call here because the backend exposes no such
// route. `footprint` and `opsec_note` are REQUIRED on the result — the UI cannot render an
// artifact without also rendering what a defender would see. Do not make them optional.

/** The blue-team view of an artifact. Never hidden, never collapsed away by default. */
export type EvasionFootprint = {
  activity: string;
  blue_view: string;
  why: string;
  telemetry: string[];
  loudness: { level: string; score: number; meaning: string; why: string };
  techniques: { id: string; name: string; tactics: string[] }[];
  spec_key?: string;
};

/** The operator-facing half. `still_recorded` is mandatory — that is the whole contract. */
export type EvasionOpsecNote = {
  loud_because: string;
  quieter: string[];
  still_recorded: string;
  tradeoff: string;
};

export type EvasionResult = {
  run_id: string;
  /** Empty when the generator failed or timed out — nothing was written, so there is no path. */
  artifact_path: string;
  techniques: string[];
  mode: string;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  footprint: EvasionFootprint;
  opsec_note: EvasionOpsecNote;
  stub: string;
};

export type EvasionBody = {
  payload_path: string;
  /** Exactly one. The backend refuses more — a build carries the footprint of ONE technique. */
  techniques: string[];
  target?: string;
  engagement_id?: string | null;
  approved: boolean;
  dangerous_ack: boolean;
};

/** Pure preview: which gate would refuse, plus the honest footprint — builds nothing. */
export type EvasionPreview = {
  rejected: { reason: string; gate: string; dangerous_flags?: string[] } | null;
  footprint: EvasionFootprint;
  opsec_note: EvasionOpsecNote;
};

export const listEvasionTechniques = (signal?: AbortSignal) =>
  getJSON<{ techniques: { technique: string; detection_spec: string }[] }>(
    "/api/evasion/techniques",
    signal
  );

export const previewEvasion = (body: EvasionBody, signal?: AbortSignal) =>
  postJSON<EvasionPreview>("/api/evasion/preview", body, signal);

export const generateEvasion = (body: EvasionBody, signal?: AbortSignal) =>
  postJSON<EvasionResult>("/api/evasion/generate", body, signal);

export type ObfuscationStatus = {
  container: string;
  up: boolean;
  live_listeners: number;
  max_live_listeners: number;
  detail: string;
};

export type DnsListener = {
  id: string;
  kind: string;
  status: string;
  container: string;
  /** A zone the OPERATOR controls and has had delegated — never the target's. */
  zone: string;
  tunnel_net: string | null;
  run_id: string;
  /** The CLIENT half, to run BY HAND on the far side. The pre-shared key is MASKED. */
  client_command: string;
  setup_note: string;
  /** What was OBSERVED about the process and its port — the evidence behind `status`. */
  liveness: string;
  started_at: string;
  stopped_at: string | null;
  engagement_id: string | null;
};

export const getObfuscationStatus = (signal?: AbortSignal) =>
  getJSON<ObfuscationStatus>("/api/obfuscation/status", signal);

export const listDnsListeners = (signal?: AbortSignal) =>
  getJSON<DnsListener[]>("/api/obfuscation/listeners", signal);

/**
 * Start a DNS-tunnel listener. GATED since build #7: `engagement_id` is REQUIRED and both
 * confirms must be explicit. A DNS tunnel is the server end of a covert exfil channel, which is
 * exactly what I2 gated the pivot listener for. A 403 carries `{gate, reason, dangerous_flags}`
 * — render the red-confirm from those flags; a 409 means the sandbox is down, the cap is hit, or
 * the listener did not stay up.
 */
export const startDnsListener = (
  body: {
    kind: string;
    zone: string;
    tunnel_net?: string;
    secret?: string | null;
    engagement_id: string;
    approved: boolean;
    dangerous_ack: boolean;
  },
  signal?: AbortSignal
) => postJSON<DnsListener>("/api/obfuscation/listeners", body, signal);

export const stopDnsListener = (lid: string, signal?: AbortSignal) =>
  fetch(`${API_URL}/api/obfuscation/listeners/${encodeURIComponent(lid)}`, {
    method: "DELETE",
    signal,
  }).then((r) => r.json() as Promise<DnsListener>);

// --- AD attack-path graph (see backend/adgraph) ---------------------------------
// Read-only graph/parse/path/technique endpoints. Every abuse command a technique
// returns is run ONLY through execCockpitStream (the gated executor) — approve-each,
// engagement-scoped. Nothing here executes anything.

export type ADNode = {
  id: string;
  type: "user" | "group" | "computer" | "domain" | "ou" | "gpo" | "container";
  label: string;
  high_value: boolean;
  owned: boolean;
  props: Record<string, unknown>;
};

export type ADCommand = { lang: string; cmd: string; truncated?: boolean };

/** The KB-grounded abuse technique for one edge (same grounded/ai_suggested shape as the
 *  kill-chain map). `commands[0]` is what the operator would send to the gated executor. */
export type ADTechnique = {
  kind: string;
  effective_kind?: string;
  title: string;
  summary: string;
  tool: string;
  destructive: boolean;
  grounded: boolean;
  ai_suggested: boolean;
  entry_id: string | null;
  entry_title: string | null;
  commands: ADCommand[];
  why: string;
};

export type ADPathEdge = {
  source: string;
  target: string;
  kind: string;
  source_label: string;
  target_label: string;
  props: Record<string, unknown>;
  technique?: ADTechnique;
};

export type ADPath = {
  node_ids: string[];
  edges: ADPathEdge[];
  length: number;
  cost: number;
};

export type ADPathResult = {
  found: boolean;
  path: ADPath | null;
  alternatives: ADPath[];
  reason: string | null;
  target: string;
  target_label: string;
};

export type ADGraph = {
  domain: string | null;
  nodes: ADNode[];
  edges: {
    source: string;
    target: string;
    kind: string;
    abusable: boolean;
    props: Record<string, unknown>;
  }[];
  stats: Record<string, number>;
  warnings: string[];
};

export type ADIngestResult = {
  graph_id: string;
  domain: string | null;
  stats: Record<string, number>;
  warnings: string[];
};

/** Ingest a captured BloodHound collection (or the built-in GOAD-style sample) into a graph. */
export const adIngest = (
  body: {
    session_id?: string | null;
    engagement_id?: string | null;
    collection?: unknown;
    use_sample?: boolean;
  },
  signal?: AbortSignal
) => postJSON<ADIngestResult>("/cockpit/ad/ingest", body, signal);

export const adGetGraph = (graphId: string, signal?: AbortSignal) =>
  getJSON<ADGraph>(`/cockpit/ad/graph/${encodeURIComponent(graphId)}`, signal);

export const adLatest = (sessionId: string, signal?: AbortSignal) =>
  getJSON<ADGraph & { graph_id: string }>(
    `/cockpit/ad/latest?session_id=${encodeURIComponent(sessionId)}`,
    signal
  );

/** Compute the route(s) to a high-value target (auto-picks Domain Admins when omitted),
 *  with the KB-grounded abuse technique attached to each hop. */
export const adComputePath = (
  body: { graph_id: string; start: string; target?: string | null; with_techniques?: boolean },
  signal?: AbortSignal
) => postJSON<ADPathResult>("/cockpit/ad/path", body, signal);

export const adTechnique = (
  body: { graph_id: string; source: string; target: string; kind: string },
  signal?: AbortSignal
) => postJSON<ADTechnique>("/cockpit/ad/technique", body, signal);

// ---- AD orchestration: the agent PROPOSES the next edge ------------------- //

/**
 * One proposed abuse step. The agent picked the EDGE from the graph's real frontier; the
 * command came from the deterministic KB-grounded technique catalog, not from the model.
 * Nothing here has run — approving it sends it to the same gated executor every other
 * cockpit command uses.
 */
export type ADProposal = {
  edge: {
    source: string;
    target: string;
    kind: string;
    source_label: string;
    target_label: string;
  };
  technique: {
    title: string | null;
    summary: string | null;
    tool: string | null;
    destructive: boolean;
    grounded: boolean;
    entry_id: string | null;
    entry_title: string | null;
  };
  command: string;
  args: string[];
  cmd_display: string;
  rationale: string;
  /** False for an edge that is inherited rights (MemberOf) — nothing to run, nothing to approve. */
  runnable: boolean;
  /**
   * Why a command is or isn't present. "ready" = we have argv. "note-only" = the technique is
   * prose, which is correct for inherited rights. "unparsable" = a real command line came back
   * that wouldn't tokenise.
   */
  resolution: "ready" | "note-only" | "unparsable";
  /**
   * A DESTRUCTIVE abuse with no runnable command. There is no executor gate to lean on here
   * because there is nothing to send to it, so this must never render as the benign
   * "nothing to run" case — whatever the operator supplies by hand changes a real domain.
   */
  destructive_unresolved: boolean;
  /** Advisory pre-check against the SAME target/scope matcher the executor uses. */
  gate_ok: boolean;
  gate_reason: string;
  dangerous_flags: string[];
  /** True when the executor WILL demand the explicit red confirm (mirrors its rule exactly). */
  requires_confirm: boolean;
  /** The technique catalog's independent "this is destructive" opinion. */
  destructive_technique: boolean;
  /** The NATIVE WINDOWS variant (PowerView/Rubeus/Mimikatz) — runs on the box over WinRM
   *  when a Windows target is selected. Empty command when the edge has no native variant. */
  windows_command: string;
  windows_args: string[];
  windows_cmd_display: string;
  windows_runnable: boolean;
  windows_dangerous_flags: string[];
  windows_requires_confirm: boolean;
};

export type ADProposeResult = {
  done: boolean;
  proposal: ADProposal | null;
  reason: string | null;
  candidates: number;
  goal: string;
  goal_label: string;
  state: { owned: string[]; traversed: string[] };
  mode: "lab" | "engagement";
  note: string;
};

export type ADAdvanceResult = {
  state: { owned: string[]; traversed: string[] };
  owned_label: string;
  objective_reached: boolean;
  remaining_frontier: number;
};

/** Ask the agent for the next edge to abuse. Executes NOTHING — returns a proposal. */
export const adOrchestratePropose = (
  body: {
    graph_id: string;
    owned: string[];
    traversed?: string[];
    target?: string | null;
    dc?: string | null;
    engagement_id?: string | null;
    avoid?: string[];
  },
  signal?: AbortSignal
) => postJSON<ADProposeResult>("/cockpit/ad/orchestrate/propose", body, signal);

/**
 * Record that an abuse step SUCCEEDED. `run_id` must name an approved run that exited 0 —
 * the walk does not advance on a refused, unapproved or failed step. Called by the UI after
 * a run the human approved; never automatically.
 */
export const adOrchestrateAdvance = (
  body: {
    graph_id: string;
    owned: string[];
    traversed: string[];
    source: string;
    target: string;
    kind: string;
    run_id?: string | null;
  },
  signal?: AbortSignal
) => postJSON<ADAdvanceResult>("/cockpit/ad/orchestrate/advance", body, signal);

/** Build (do NOT run) the collector ExecRequest. The returned `request` is sent to
 *  execCockpitStream to run through the gated executor (approve-each, scope-locked DC). */
export type ADCollectPreview = {
  request: ExecPayload & { engagement_id: string | null };
  preview_argv: string[];
  params: Record<string, unknown>;
  note: string;
};
export const adCollectPreview = (
  body: {
    engagement_id: string;
    session_id?: string | null;
    domain: string;
    username: string;
    dc: string;
    password?: string | null;
    nthash?: string | null;
    nameserver?: string | null;
    collection_methods?: string;
    dns_tcp?: boolean;
  },
  signal?: AbortSignal
) => postJSON<ADCollectPreview>("/cockpit/ad/collect/preview", body, signal);

// --- detection footprint: the PURPLE-TEAM view (see backend/detection/) -------------------
//
// READ-ONLY ANNOTATION. Every call here DESCRIBES what a defender would see for a command that
// has already been (or is about to be) approved and run through the gated executor: the ATT&CK
// technique + tactic, the telemetry it generates, the SigmaHQ rule that would fire, and how
// loud it is. Nothing here runs anything or changes any gate.
//
// THE LINE: this shows the footprint. It is not, and must never become, evasion guidance —
// there is no "make this quieter" call, by design. A "quiet" rating marks a gap in the
// DEFENDER's coverage, not a lane for the operator.

/** Loud-vs-quiet signal rating. Higher = more likely to raise a high-confidence alert. */
export type Loudness = "quiet" | "moderate" | "notable" | "loud";

export type DetectionTactic = {
  id: string;
  name: string;
  /** The name this tactic used to carry (ATT&CK v19 renamed TA0005 to "Stealth"). */
  also_known_as?: string | null;
  url?: string;
};

export type DetectionTechnique = {
  id: string;
  name: string;
  url: string;
  tactics?: DetectionTactic[];
  /** Present on the compact tag instead of `tactics`. */
  tactic_ids?: string[];
  tactic_names?: string[];
  data_components?: string[];
  log_sources?: string[];
  stealth?: boolean;
  /** "grounded" (curated ATT&CK/SigmaHQ map) or "ai_suggested" (model reading). */
  source?: "grounded" | "ai_suggested";
  known?: boolean;
};

/** The compact tag carried by every planned step and recorded run. */
export type DetectionTag = {
  activity: string;
  grounded: boolean;
  techniques: DetectionTechnique[];
  tactics: DetectionTactic[];
  stealth: boolean;
  loudness: Loudness;
  loudness_score: number;
  signals: string[];
};

/** One real SigmaHQ rule that would fire. `url` points at the rule in the public repo. */
export type SigmaRuleRef = {
  id: string;
  title: string;
  path?: string;
  url: string;
  level: string;
};

/** An argument-level signal — an escalation, or a stealth-shaped flag SURFACED (never advised). */
export type DetectionSignal = {
  id: string;
  label: string;
  note: string;
  stealth: boolean;
  louder: boolean;
  techniques: string[];
};

/**
 * The OFFENSIVE half (D10) — the operator-side counterpart to the detection footprint.
 * Present only when the footprint was requested with `include_opsec`, and only for a
 * command the curated map covers (or, ai_suggested, one the model could read). Its
 * `still_recorded` is always populated — the note is honest about its own limits.
 */
export type DetectionOpsec = {
  grounded: boolean;
  ai_suggested: boolean;
  /** What specifically generates the signal. */
  loud_because: string;
  /** Quieter tradecraft / knobs. */
  quieter: string[];
  /** What logs it anyway, even done the quieter way. Never empty. */
  still_recorded: string;
  /** What the quieter path costs — time, reliability, coverage. */
  tradeoff: string;
};

/** The full defender's-eye view of one command. */
export type DetectionFootprint = {
  command: string;
  args: string[];
  argv: string;
  activity: string;
  /** True = every field below comes from the curated ATT&CK/SigmaHQ map. */
  grounded: boolean;
  /** True = the model's own reading (render with a "verify" badge, like a composed step). */
  ai_suggested: boolean;
  matched_on: string;
  spec_key?: string;
  techniques: DetectionTechnique[];
  tactics: DetectionTactic[];
  stealth: { present: boolean; techniques: string[]; note: string };
  /** Concrete things a defender would see — event ids, log lines, flow shapes. */
  telemetry: string[];
  sigma: SigmaRuleRef[];
  loudness: { level: Loudness | ""; score: number; meaning: string; why: string };
  blue_view: string;
  signals: DetectionSignal[];
  why: string;
  sources: Record<string, string>;
  run_id?: string;
  mode?: string;
  /** The offensive half — only when requested and available; null otherwise. */
  opsec?: DetectionOpsec | null;
};

export type DetectionSources = {
  attack: string;
  attack_attribution: string;
  attack_version: string;
  sigma: string;
  sigma_license: string;
  techniques: number;
  specs: number;
  sigma_rules: number;
  arg_signals: number;
  loudness_scale: { level: Loudness; score: number; meaning: string }[];
  tactic_aliases: Record<string, string>;
  the_line: string;
  read_only: boolean;
};

export type DetectionRunsOut = {
  session_id: string;
  runs: {
    run_id: string;
    command: string;
    args: string[];
    target: string;
    mode: string;
    started_at: string;
    step_id: string | null;
    attck: DetectionTag | null;
  }[];
  summary: {
    tagged: number;
    untagged: number;
    techniques: DetectionTechnique[];
    tactics: DetectionTactic[];
    stealth: boolean;
    loudest: Loudness | "";
    loudest_score: number;
  };
};

/** The footprint for one command. `allow_llm: false` gives a purely grounded answer.
 *  `include_opsec` (D10) additionally attaches the offensive `opsec` block. */
export const detectionFootprint = (
  body: {
    command?: string;
    args?: string[];
    argv?: string;
    context?: string;
    allow_llm?: boolean;
    include_opsec?: boolean;
  },
  signal?: AbortSignal
) => postJSON<DetectionFootprint>("/detection/footprint", body, signal);

/** The footprint for an attack-path step (annotates its first real command). */
export const detectionFootprintStep = (
  step: AttackStep,
  allowLlm = true,
  signal?: AbortSignal,
  includeOpsec = false
) =>
  postJSON<DetectionFootprint>(
    "/detection/footprint/step",
    { step, allow_llm: allowLlm, include_opsec: includeOpsec },
    signal
  );

/** The footprint for a recorded run — what blue saw when it actually ran. */
export const detectionFootprintRun = (
  runId: string,
  allowLlm = true,
  signal?: AbortSignal
) =>
  getJSON<DetectionFootprint>(
    `/detection/footprint/run/${encodeURIComponent(runId)}?allow_llm=${allowLlm}`,
    signal
  );

/** ATT&CK tags for every recorded run on an engagement, plus a coverage summary. */
export const detectionRuns = (sessionId: string, signal?: AbortSignal) =>
  getJSON<DetectionRunsOut>(
    `/detection/runs?session_id=${encodeURIComponent(sessionId)}`,
    signal
  );

/** Where the knowledge comes from + the line the panel holds (for the About box). */
export const detectionSources = (signal?: AbortSignal) =>
  getJSON<DetectionSources>("/detection/sources", signal);

// --- build #8 Tasks 3 & 4: web-exploit + privesc drafting ------------------------
//
// PROPOSE / GROUND / DRAFT ONLY. Both endpoints return DATA. Neither sends a request nor
// runs a command: the human fires the drafted step through the already-gated executor or
// repeater, where scope + approval + the danger red-confirm are re-checked (D18 unchanged).

/** A drafted web exploit for one finding. `dangerous` mirrors what the red-confirm will say. */
export type WebExploitDraft = {
  /** False when the finding's bug class has no drafted exploit — say so, never invent one. */
  applicable: boolean;
  /** sqli | ssrf | idor | xss | param-pollution | lfi | "" */
  bug_class: string;
  command: string;
  args: string[];
  /** A raw HTTP request to fire through the repeater, when that is the right delivery. */
  request: string;
  explanation: string;
  citations: { entry_id?: string; title?: string }[];
  /** "executor" | "repeater" — which gated surface the human fires this through. */
  delivery: string;
  dangerous: boolean;
  hypothesis: string;
};

/** Draft the concrete exploit for a web finding already in state (by fingerprint). */
export const draftWebExploit = (
  sessionId: string,
  body: { fingerprint?: string; finding?: Record<string, unknown> },
  signal?: AbortSignal
) =>
  postJSON<WebExploitDraft>(
    `/sessions/${encodeURIComponent(sessionId)}/webexploit/draft`,
    body,
    signal
  );

/** One privesc vector parsed out of pasted linpeas/winpeas output. */
export type PrivescVector = {
  /** suid | sudo | capabilities | pwnkit | kernel | writable-passwd | se-impersonate | … */
  kind: string;
  detail: string;
  severity: string;
  evidence: string;
  platform: string;
};

export type PrivescDraft = {
  applicable: boolean;
  vector: PrivescVector | null;
  command: string;
  args: string[];
  /** Set when the escalation is a shell one-liner run on the foothold rather than a tool. */
  shell_line: string;
  explanation: string;
  hypothesis: string;
  citations: { entry_id?: string; title?: string }[];
  dangerous: boolean;
};

/** Paste linpeas/winpeas output; get the identified vectors + a drafted escalation. */
export const ingestPrivesc = (sessionId: string, output: string, signal?: AbortSignal) =>
  postJSON<{ vectors: PrivescVector[]; draft: PrivescDraft }>(
    `/sessions/${encodeURIComponent(sessionId)}/privesc/ingest`,
    { output },
    signal
  );

/** One curated command family as the catalog holds it. */
export type DetectionSpec = {
  key: string;
  label: string;
  techniques: string[];
  loudness: Loudness;
  loudness_score: number;
  /** The defender-side description. Guarded server-side against drifting into evasion. */
  blue_view: string;
  why_rating: string;
  telemetry: string[];
  sigma: SigmaRuleRef[];
  /** The offensive half (D10), when this family has a curated OPSEC note. */
  opsec: {
    loud_because: string;
    quieter: string[];
    /** Never empty — the honesty invariant. */
    still_recorded: string;
    tradeoff: string;
  } | null;
};

/** The WHOLE curated map — every command family and argument signal HackPit knows. */
export type DetectionCatalog = {
  specs: DetectionSpec[];
  signals: DetectionSignal[];
  sources: Pick<DetectionSources, "attack" | "attack_attribution" | "sigma" | "sigma_license">;
};

export const detectionCatalog = (signal?: AbortSignal) =>
  getJSON<DetectionCatalog>("/detection/catalog", signal);

/** One ATT&CK technique as the panel renders it, with the Sigma rules that reference it. */
export type DetectionTechniqueDetail = DetectionTechnique & {
  sigma?: SigmaRuleRef[];
};

export const detectionTechnique = (id: string, signal?: AbortSignal) =>
  getJSON<DetectionTechniqueDetail>(
    `/detection/technique/${encodeURIComponent(id.trim().toUpperCase())}`,
    signal
  );

/** The COMPACT ATT&CK tag for one command — deterministic, catalog-only, never the LLM.
 *  `tag: null` means the curated map does not cover it; ask for the full footprint then. */
export const detectionTag = (
  body: { command?: string; args?: string[]; argv?: string },
  signal?: AbortSignal
) =>
  postJSON<{ argv: string; tag: DetectionTag | null }>("/detection/tag", body, signal);

// --- live sessions: catch + drive ONE shell by hand (see backend/cockpit/session.py) ---
//
// TWO GATES, both server-side and both load-bearing:
//   START  is a GATED COMMAND — startSession() goes through the same executor gates a
//          one-shot command does (approve-each + heuristic red-confirm + mode gate,
//          argv-only). A listener trips the heuristic, so dangerous_ack is required.
//   STDIN  is *** HUMAN-ONLY *** — writeSessionStdin() exists to serve a HUMAN typing
//          into the panel. Nothing agent-driven may ever call it; the backend locks that
//          with a source scan. Do NOT wire this into the loop or any automated flow.

/** The public state of one live session. `sid` is the LIVE SESSION id; `session_id`
 *  keeps its repo-wide meaning — the engagement the transcript is recorded against. */
export type SessionInfo = {
  sid: string;
  state: "active" | "exited" | "killed";
  /** Which sandbox this session is bound to — drives the panel's mode banner. */
  mode: "lab" | "engagement";
  container: string;
  /** The gate-validated declared bind target. */
  target: string;
  command: string;
  args: string[];
  run_id: string;
  engagement_id: string | null;
  session_id: string | null;
  step_id: string | null;
  started_at: string;
  finished_at: string | null;
  exit_code: number | null;
  truncated: boolean;
  detail: string;
};

export type SessionStatus = {
  live: number;
  total: number;
  max_live: number;
  idle_timeout_seconds: number;
  max_lifetime_seconds: number;
};

/** One event from a session's output stream. */
export type SessionEvent = {
  seq: number;
  type: "start" | "stdout" | "stderr" | "stdin" | "exit" | "killed" | "error";
  line?: string;
  reason?: string;
  code?: number | null;
  state?: string;
  [k: string]: unknown;
};

export type SessionStartPayload = {
  command: string;
  args: string[];
  /** The DECLARED bind target. Validated server-side by the mode's target-lock. */
  target: string;
  approved: boolean;
  dangerous_ack: boolean;
  engagement_id?: string | null;
  session_id?: string | null;
  step_id?: string | null;
};

export const getSessionStatus = (signal?: AbortSignal) =>
  getJSON<SessionStatus>("/cockpit/session/status", signal);

export const listLiveSessions = (signal?: AbortSignal) =>
  getJSON<SessionInfo[]>("/cockpit/session", signal);

/** Start ONE long-lived session. A gate failure comes back as 403 (nothing started)
 *  with { detail: { gate, reason } }; a 409 means unavailable or at the session cap. */
export const startSession = (payload: SessionStartPayload, signal?: AbortSignal) =>
  postJSON<SessionInfo>("/cockpit/session/start", payload, signal);

/**
 * *** HUMAN-ONLY *** — send one line to a live session's stdin.
 *
 * Call this ONLY from a human's direct UI action (the panel's input line). A live
 * session is already approved and already running, so anything automated typing into
 * it would be executing un-gated commands. The backend refuses to let the agent path
 * reach this at all; keep the frontend honest to the same rule.
 */
export const writeSessionStdin = (sid: string, data: string, signal?: AbortSignal) =>
  postJSON<SessionInfo>(
    `/cockpit/session/${encodeURIComponent(sid)}/stdin`,
    { data },
    signal
  );

export const killSession = (sid: string, signal?: AbortSignal) =>
  postJSON<SessionInfo>(`/cockpit/session/${encodeURIComponent(sid)}/kill`, {}, signal);

/**
 * Stream a session's output. Read-only — subscribing never writes to the process.
 * `after` resumes from a sequence number so a reconnect replays the rolling tail.
 * Resolves when the session finishes and the stream closes.
 */
export async function streamSession(
  sid: string,
  onEvent: (ev: SessionEvent) => void,
  after = -1,
  signal?: AbortSignal
): Promise<void> {
  let res: Response;
  const url = `${API_URL}/cockpit/session/${encodeURIComponent(sid)}/stream?after=${after}`;
  try {
    res = await fetch(url, { headers: { Accept: "text/event-stream" }, signal });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok || !res.body) {
    throw new ApiError(res.status, await errorMessage(res, `Stream failed (${res.status}).`));
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let sep: number;
    while ((sep = buf.indexOf("\n\n")) >= 0) {
      const frame = buf.slice(0, sep);
      buf = buf.slice(sep + 2);
      const dataLine = frame.split("\n").find((l) => l.startsWith("data:"));
      if (!dataLine) continue;
      try {
        onEvent(JSON.parse(dataLine.slice(5).trim()) as SessionEvent);
      } catch {
        /* ignore a malformed frame */
      }
    }
  }
}

// ---- :code scan (STATIC AppSec analysis) ---------------------------------- //
//
// Read-only static analysis: the backend runs Semgrep/Bandit over a codebase path
// and returns what they found. Nothing here executes the scanned code, and none of
// it touches the engagement / executor / target-lock model.

export type CodeScanTool = {
  name: string;
  installed: boolean;
  path: string | null;
  /** Exact command to install a missing scanner. */
  install_hint: string;
};

export type CodeScanRuleset = { key: string; label: string };

export type CodeScanTools = {
  tools: CodeScanTool[];
  /** True when at least Semgrep is available. */
  ready: boolean;
  /** Path of the default (resolved) offline ruleset. */
  ruleset: string;
  /** Offline rulesets the picker offers (bundled / python-js-ts / languages). */
  rulesets?: CodeScanRuleset[];
};

export type CodeScanSeverity = "critical" | "high" | "medium" | "low" | "info";

export type CodeScanFinding = {
  rule_id: string;
  /** "semgrep" | "bandit" | "bandit+semgrep" when both tools agree. */
  tool: string;
  severity: CodeScanSeverity;
  file: string;
  line: number;
  message: string;
  category: string;
  cwe: string | null;
  owasp: string | null;
  confidence: string | null;
  /** The scanner's own severity word, before it was mapped. */
  tool_severity: string | null;
  tools: string[];
  /** KB technique behind this defect — null when nothing matched confidently. */
  kb_entry_id: string | null;
  kb_title: string | null;
};

export type CodeScanSummary = {
  total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_tool: Record<string, number>;
  files_affected: number;
};

export type CodeScanResult = {
  path: string;
  files_scanned: number;
  duration_s: number;
  tools_run: string[];
  ruleset: string;
  summary: CodeScanSummary;
  findings: CodeScanFinding[];
  /** Non-fatal notes: a scanner skipped, rule errors, partial results. */
  warnings: string[];
  /** Always true — the scanned code is parsed, never executed. */
  static_only: boolean;
};

export const getCodeScanTools = (signal?: AbortSignal) =>
  getJSON<CodeScanTools>("/codescan/tools", signal);

export const runCodeScan = (
  payload: {
    path: string;
    timeout_s?: number;
    semgrep_config?: string | null;
    use_bandit?: boolean;
  },
  signal?: AbortSignal
) => postJSON<CodeScanResult>("/codescan/scan", payload, signal);

export type CodeScanReport = { markdown: string; filename: string };

/** Render the scan you are looking at as a Markdown report (no re-scan). */
export const renderCodeScanReport = (result: CodeScanResult, signal?: AbortSignal) =>
  postJSON<CodeScanReport>("/codescan/report", result, signal);

// ---- tool arsenal (curated catalog + invocation templates) ---------------- //
//
// Read-only catalog. A template is a STRING to copy; it becomes a command only by
// going through the gated cockpit executor with an explicit human approval.

export type ArsenalTemplate = {
  label: string;
  /** Invocation with <placeholders> — copy and fill. */
  template: string;
  note: string;
  placeholders: string[];
};

export type ArsenalTool = {
  name: string;
  aliases: string[];
  category: string;
  purpose: string;
  phases: string[];
  techniques: string[];
  docs: string;
  templates: ArsenalTemplate[];
  /** Common flags — informational only; the executor has no allowlist. */
  flags: { flag: string; what: string }[];
  /** KB entry documenting this tool; null when the KB doesn't (never fabricated). */
  kb_entry_id: string | null;
  kb_title: string | null;
  /** "" for the Linux sandbox; "windows" for PowerShell/.NET tooling. */
  platform: string;
  /** False for tools that cannot run on the Linux sandbox at all (D9). */
  runs_here: boolean;
};

/**
 * Which catalogued tools the sandbox ACTUALLY has (D7).
 *
 * `available: false` means the probe could not run — availability is UNKNOWN, NOT that the
 * tools are missing. The UI must say so rather than showing a wall of false gaps.
 */
export type ToolReconciliation = {
  checked_at: string | null;
  container: string | null;
  available: boolean;
  detail: string;
  present_count: number;
  /** Catalogued Linux tools the sandbox does not have — a real gap. */
  missing: string[];
  /** Windows-only entries: cannot run here by construction, NOT a gap to close. */
  windows_only: string[];
  loot?: {
    mount: string;
    host_root: string;
    sandboxes_with_loot: string[];
    lab_sandbox_has_loot: boolean;
  };
};

export const getToolReconciliation = (signal?: AbortSignal) =>
  getJSON<ToolReconciliation>("/tools", signal);

// --- structured engagement state (Phase 2) --------------------------------------- //

/** Something addressable. */
export type StateHost = {
  address: string;
  hostname: string;
  os: string;
  status: string;
  /** OSCP exam flags (Phase 4 item 5). */
  local_txt?: string;
  proof_txt?: string;
  /** "" (none) | "foothold" (local only) | "owned" (proof captured). */
  ownership?: string;
  source_run_id: string | null;
  first_seen: string;
  last_seen: string;
};

/** Something listening on a host. */
export type StateService = {
  address: string;
  port: number;
  proto: string;
  name: string;
  product: string;
  version: string;
  state: string;
  banner: string;
  source_run_id: string | null;
};

/** Something reachable over HTTP. */
export type StateEndpoint = {
  url: string;
  method: string;
  status: number | null;
  title: string;
  length: number | null;
  tech: string;
  params: string[];
  source_run_id: string | null;
};

/** Something you can authenticate with. `secret` is the real value — see the panel's
 *  reveal control; it is masked until the operator asks for it. */
export type StateCredential = {
  kind: string;
  principal: string;
  domain: string;
  secret: string;
  validated: boolean | null;
  note: string;
  source_run_id: string | null;
};

/** Something that is wrong. */
export type StateFinding = {
  title: string;
  severity: string;
  target: string;
  evidence: string;
  tool: string;
  reference: string;
  fingerprint: string;
  source_run_id: string | null;
};

/** One node of the Pentest Task Tree. `task_id` is a dotted path: "1", "1.2", "1.2.3". */
export type StateTask = {
  task_id: string;
  title: string;
  status: "todo" | "done" | "n/a";
  why: string;
  evidence_run_id: string | null;
  depth: number;
  parent_id: string | null;
};

export type SessionState = {
  counts: {
    hosts: number;
    services: number;
    endpoints: number;
    credentials: number;
    findings: number;
  };
  hosts: StateHost[];
  services: StateService[];
  endpoints: StateEndpoint[];
  credentials: StateCredential[];
  findings: StateFinding[];
  tasks: StateTask[];
  task_progress: { total: number; todo: number; done: number; na: number };
};

export const getSessionState = (sessionId: string, signal?: AbortSignal) =>
  getJSON<SessionState>(
    `/sessions/${encodeURIComponent(sessionId)}/state`,
    signal
  );

/**
 * Fill a command's credential placeholders (<user>/<password>/<hash>/<domain>) from one
 * captured credential (step 14). The placeholder→field mapping lives server-side, so the
 * UI never re-implements it. Returns the filled command and which placeholders were filled.
 * Fills nothing but credential placeholders; <target> and operational ones are untouched.
 */
export async function fillCredential(
  sessionId: string,
  command: string,
  cred: { kind: string; principal: string; domain: string },
  signal?: AbortSignal
): Promise<{ command: string; filled: string[] }> {
  const res = await fetch(
    `${API_URL}/sessions/${encodeURIComponent(sessionId)}/credentials/fill`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command, ...cred }),
      signal,
    }
  );
  if (!res.ok) throw new ApiError(res.status, `Could not fill the credential (${res.status}).`);
  return (await res.json()) as { command: string; filled: string[] };
}

/** Seed the task tree from the composed plan's phases. Idempotent server-side: a session
 *  that already has tasks is left alone, so this can never wipe recorded progress. */
export async function seedSessionTasks(
  sessionId: string,
  signal?: AbortSignal
): Promise<{ tasks: StateTask[] }> {
  const res = await fetch(
    `${API_URL}/sessions/${encodeURIComponent(sessionId)}/state/tasks/seed`,
    { method: "POST", headers: { "Content-Type": "application/json" }, signal }
  );
  if (!res.ok) throw new ApiError(res.status, `Could not seed the task tree (${res.status}).`);
  return (await res.json()) as { tasks: StateTask[] };
}

export type ArsenalResponse = {
  total: number;
  categories: string[];
  placeholders: Record<string, string>;
  tools: ArsenalTool[];
  /** Always true — this is a catalog, not an engine. */
  executes_nothing: boolean;
};

export const getArsenal = (signal?: AbortSignal) =>
  getJSON<ArsenalResponse>("/arsenal", signal);

/** The tools worth reaching for in a phase / for a technique — the SAME selection the
 *  planner's prompt reference uses, so the catalog can show what the planner would pick. */
export const suggestArsenal = (
  opts: { phase?: string | null; q?: string | null; limit?: number },
  signal?: AbortSignal
) => {
  const p = new URLSearchParams();
  if (opts.phase) p.set("phase", opts.phase);
  if (opts.q) p.set("q", opts.q);
  if (opts.limit) p.set("limit", String(opts.limit));
  return getJSON<ArsenalResponse>(`/arsenal/suggest?${p.toString()}`, signal);
};

/** One rendered invocation. `ready: false` means a placeholder is still unfilled — it stays
 *  VISIBLE rather than being guessed, which is the whole point of rendering server-side. */
export type ArsenalInvocation = {
  tool: string;
  label: string;
  cmd: string;
  note: string;
  /** Placeholders with no value — still visible in `cmd`. */
  unfilled: string[];
  ready: boolean;
};

export type ArsenalRender = { tool: string; invocations: ArsenalInvocation[] };

/** Render a tool's templates against a target. Returns STRINGS — nothing is executed.
 *  A rendered command still reaches a target only through the gated executor. */
export const renderArsenalTool = (
  name: string,
  target?: string | null,
  signal?: AbortSignal
) =>
  getJSON<ArsenalRender>(
    `/arsenal/render/${encodeURIComponent(name)}` +
      (target ? `?target=${encodeURIComponent(target)}` : ""),
    signal
  );

// ---- Windows targets (WinRM driver — saved connection profiles) ----------- //

/** A saved Windows target, MASKED — the secret is never returned (only `has_secret`). */
export type WindowsProfile = {
  profile_id: string;
  name: string;
  host: string;
  transport: string;
  port: number;
  username: string;
  auth_kind: "password" | "ntlm-hash";
  has_secret: boolean;
  domain: string;
  created_at: string;
};

/** Create/update a profile. `secret` is write-only; an empty secret on update keeps the
 *  stored one. `from_credential` fills the account + secret from a captured vault credential
 *  SERVER-SIDE, so the secret never round-trips through the browser. */
export type WindowsProfileInput = {
  name: string;
  host: string;
  username: string;
  transport?: string;
  port?: number;
  auth_kind?: "password" | "ntlm-hash";
  secret?: string;
  domain?: string;
  from_credential?: {
    session_id: string;
    kind: string;
    principal: string;
    domain: string;
  } | null;
};

export type WindowsStatus = {
  profiles: number;
  pywinrm_installed: boolean;
  detail: string;
};

/** Result of the human-initiated connectivity smoke test (hardcoded `whoami`). */
export type WindowsTestResult = {
  ok: boolean;
  host: string;
  exit_code?: number | null;
  stdout?: string;
  stderr?: string;
  error?: string;
};

async function putJSON<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
      signal,
    });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    throw new ApiError(res.status, await errorMessage(res, `Request failed (${res.status}).`));
  }
  return (await res.json()) as T;
}

async function delJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, { method: "DELETE", signal });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    throw new ApiError(res.status, await errorMessage(res, `Request failed (${res.status}).`));
  }
  return (await res.json()) as T;
}

export const getWindowsStatus = (signal?: AbortSignal) =>
  getJSON<WindowsStatus>("/cockpit/windows/status", signal);

export const listWindowsProfiles = (signal?: AbortSignal) =>
  getJSON<WindowsProfile[]>("/cockpit/windows/profiles", signal);

export const createWindowsProfile = (input: WindowsProfileInput, signal?: AbortSignal) =>
  postJSON<WindowsProfile>("/cockpit/windows/profiles", input, signal);

export const updateWindowsProfile = (
  profileId: string,
  input: Partial<WindowsProfileInput>,
  signal?: AbortSignal
) =>
  putJSON<WindowsProfile>(
    `/cockpit/windows/profiles/${encodeURIComponent(profileId)}`,
    input,
    signal
  );

export const deleteWindowsProfile = (profileId: string, signal?: AbortSignal) =>
  delJSON<{ profile_id: string; deleted: boolean }>(
    `/cockpit/windows/profiles/${encodeURIComponent(profileId)}`,
    signal
  );

/** Human-initiated connectivity smoke test — runs a hardcoded `whoami` over WinRM. */
export const testWindowsProfile = (profileId: string, signal?: AbortSignal) =>
  postJSON<WindowsTestResult>(
    `/cockpit/windows/profiles/${encodeURIComponent(profileId)}/test`,
    {},
    signal
  );

// ---- out-of-band canary (build #13 part 3) ------------------------------- //

/** The canary's configuration, MASKED. `has_secret` is the only thing said about the
 *  read secret — the value is never sent to the browser. */
export type OOBConfig = {
  zone: string;
  host: string;
  answer_ip: string;
  http_port: number;
  dns_port: number;
  ssh_user: string;
  ssh_port: number;
  ssh_key_path: string;
  has_secret: boolean;
  cursor: number;
  deployed_at: string;
  updated_at: string;
};

export type OOBNsRecord = { name: string; type: string; value: string; note: string };

/** The exact records to paste at the registrar. An A record alone is the usual mistake and
 *  the `warning` says so. */
export type OOBNsDelegation = {
  zone: string;
  parent_zone: string;
  records: OOBNsRecord[];
  zonefile: string;
  warning: string;
};

export type OOBTemplate = {
  id: string;
  vuln_class: string;
  title: string;
  sink: string;
  proves: string;
  note: string;
};

export type OOBPayload = OOBTemplate & { payload: string };

export type OOBStatus = {
  configured: boolean;
  config: OOBConfig | null;
  ns: OOBNsDelegation | null;
  templates: OOBTemplate[];
  vuln_classes: string[];
  remote_dir: string;
};

export type OOBToken = {
  token: string;
  engagement_id: string;
  step_id: string | null;
  note: string;
  at: string;
};

export type OOBMintResult = { token: OOBToken; zone: string; payloads: OOBPayload[] };

/** A hit, joined to the mint record that explains it. `correlated: false` means it arrived
 *  but could not be attributed — kept deliberately, never dropped. */
export type OOBHit = {
  kind: "dns" | "http";
  token: string | null;
  qname?: string;
  qtype?: string;
  method?: string;
  path?: string;
  host?: string;
  source_ip: string;
  at: string;
  seq: number;
  correlated: boolean;
  engagement_id: string | null;
  step_id: string | null;
  note: string;
};

export type OOBPollResult = {
  hits: OOBHit[];
  cursor: number;
  after: number;
  filed: number;
  unfiled: (OOBHit & { reason: string })[];
};

/** One verify check. `not-run` is a first-class status and is never folded into a pass. */
export type OOBCheck = {
  check: string;
  status: "pass" | "fail" | "not-run";
  detail: string;
};

export type OOBVerifyResult = {
  ok: boolean;
  checks: OOBCheck[];
  not_run?: string[];
};

export type OOBDeployStep = {
  step: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

export type OOBDeployResult = {
  ok: boolean;
  target: { host: string; user: string; port: number; remote_dir: string; zone: string };
  bytes_sent: number;
  steps: OOBDeployStep[];
};

export type OOBConfigInput = {
  zone: string;
  host: string;
  answer_ip?: string;
  http_port?: number;
  dns_port?: number;
  ssh_user?: string;
  ssh_port?: number;
  ssh_key_path?: string;
  /** Blank on edit KEEPS the stored secret — it is never returned, so it cannot be re-sent. */
  read_secret?: string;
};

export const getOOB = (signal?: AbortSignal) => getJSON<OOBStatus>("/oob", signal);

export const saveOOBConfig = (input: OOBConfigInput, signal?: AbortSignal) =>
  postJSON<{ config: OOBConfig; ns: OOBNsDelegation; note: string }>("/oob/config", input, signal);

export const deleteOOBConfig = (signal?: AbortSignal) =>
  delJSON<{ removed: boolean; note: string }>("/oob/config", signal);

/** Mint a token for a step and render the payloads that carry it. One call, because a
 *  payload with no mint record behind it correlates to nothing. */
export const mintOOBToken = (
  input: { engagement_id: string; step_id?: string | null; note?: string; vuln_class?: string | null },
  signal?: AbortSignal
) => postJSON<OOBMintResult>("/oob/mint", input, signal);

export const listOOBTokens = (engagementId: string, signal?: AbortSignal) =>
  getJSON<{ engagement_id: string; tokens: OOBToken[] }>(
    `/oob/tokens/${encodeURIComponent(engagementId)}`,
    signal
  );

/** Fetch what is new, correlate it, file it. Omit `after` to use (and advance) the cursor. */
export const pollOOB = (after?: number | null, signal?: AbortSignal) =>
  postJSON<OOBPollResult>("/oob/poll", { after: after ?? null }, signal);

/** GATED. Carries no destination — the server resolves the VPS from its own config store. */
export const deployOOB = (approved: boolean, signal?: AbortSignal) =>
  postJSON<OOBDeployResult>("/oob/deploy", { approved, restart: true }, signal);

export const verifyOOB = (signal?: AbortSignal) =>
  postJSON<OOBVerifyResult>("/oob/verify", {}, signal);

// ---- listener exposure: local profiles + the C2 redirector (build #13) ---- //

export type ListenerProfile = {
  ip: string;
  /** local = an interface on this machine; remote = the configured VPS. */
  destination: "local" | "remote";
  container: string;
  kinds: string[];
  extra: [number, string][];
  engagement: string | null;
  ack_wildcard: boolean;
  ack_public: boolean;
};

export type ExposureStatus = {
  profile: ListenerProfile | null;
  presets: string[];
  exposable: string[];
  kinds: Record<string, { port: number; proto: string }>;
  /** Never claims a state it has not observed: none | pending-restart | active | drifted |
   *  unknown | remote. */
  state: string;
  published: Record<string, [string, string]>;
  expected: [number, string][];
  note: string;
};

export type ExposureWriteResult = {
  written: string;
  ports: [number, string][];
  warnings: string[];
  command?: string[];
  note: string;
};

/** What a remote profile actually makes reachable, in the words it needs to be said in. */
export type RedirectorDescribe = {
  host: string;
  remote_dir: string;
  tcp_ports: number[];
  udp_ports: number[];
  tunnel_map: { public: number; tunnel: number; proto: string }[];
  forwarder: string[];
  reverse_tunnel: string[];
  udp_bridges: { port: string; where: string; command: string; why: string }[];
  exposure: string;
  aup: string;
  not_authenticated: string;
  teardown: string;
};

export type RemoteExposureStatus = {
  profile: ListenerProfile | null;
  remote_dir: string;
  ports?: [number, string][];
  warnings?: string[];
  describe?: RedirectorDescribe;
  note?: string;
};

export type RedirectorDeployResult = {
  ok: boolean;
  artifact: string;
  target: { host: string; user: string; port: number; remote_dir: string; zone: string };
  bytes_sent?: number;
  steps: OOBDeployStep[];
  describe?: RedirectorDescribe;
};

export type ProfileInput = {
  ip?: string;
  container?: string;
  kinds?: string[];
  extra?: [number, string][];
  engagement?: string | null;
  ack_wildcard?: boolean;
  ack_public?: boolean;
  approved?: boolean;
};

export const getExposure = (signal?: AbortSignal) =>
  getJSON<ExposureStatus>("/cockpit/exposure", signal);

export const writeExposureProfile = (input: ProfileInput, signal?: AbortSignal) =>
  postJSON<ExposureWriteResult>("/cockpit/exposure/profile", input, signal);

/** Recreates the container — kills every listener, session and job inside it. */
export const applyExposureProfile = (input: ProfileInput, signal?: AbortSignal) =>
  postJSON<{ applied: boolean; command: string[] } & ExposureStatus>(
    "/cockpit/exposure/apply",
    input,
    signal
  );

export const deleteExposureProfile = (signal?: AbortSignal) =>
  delJSON<{ removed: boolean; note: string }>("/cockpit/exposure/profile", signal);

export const getRemoteExposure = (signal?: AbortSignal) =>
  getJSON<RemoteExposureStatus>("/cockpit/exposure/remote", signal);

export const writeRemoteExposure = (input: ProfileInput, signal?: AbortSignal) =>
  postJSON<{ written: string; ports: [number, string][]; note: string }>(
    "/cockpit/exposure/remote",
    input,
    signal
  );

export const deleteRemoteExposure = (signal?: AbortSignal) =>
  delJSON<{ removed: boolean; note: string }>("/cockpit/exposure/remote", signal);

/** GATED. Carries only an approval — the host and the port list are both resolved
 *  server-side, so a request can never widen what becomes publicly reachable. */
export const deployRedirector = (approved: boolean, signal?: AbortSignal) =>
  postJSON<RedirectorDeployResult>("/cockpit/exposure/remote/deploy", { approved }, signal);

export const stopRedirector = (approved: boolean, signal?: AbortSignal) =>
  postJSON<RedirectorDeployResult>("/cockpit/exposure/remote/stop", { approved }, signal);
