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
  commands: Code[];
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

export type AttackPath = {
  goal: string;
  target_type: string | null;
  /** Target (IP/host/URL) parsed from the goal + substituted into commands. */
  target: string | null;
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
  method: "PATCH" | "DELETE",
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

/** Compose a guided attack path. Slow: the local model can take a minute+. */
export const composeAttackPath = (
  goal: string,
  target_type?: string | null,
  scope_text?: string | null,
  signal?: AbortSignal
) =>
  postJSON<AttackPath>(
    "/attack-path",
    { goal, target_type: target_type ?? null, scope_text: scope_text ?? null },
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

/** Draft (or re-draft) a pentest report for the session. Slow on local models. */
export const generateReport = (id: string, signal?: AbortSignal) =>
  postJSON<Report>(`/sessions/${encodeURIComponent(id)}/report`, {}, signal);

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
  /** "lab" (isolated lab) or "engagement" (real authorized target, Wall-A sandbox). */
  mode?: "lab" | "engagement";
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
  | { type: "start"; run_id: string; command: string; args: string[]; target: string; mode?: "lab" | "engagement"; started_at: string }
  | { type: "stdout"; line: string }
  | { type: "stderr"; line: string }
  | { type: "exit"; run_id: string; code: number | null; finished_at: string }
  | { type: "rejected"; gate: string; reason: string }
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
        onEvent(JSON.parse(dataLine.slice(5).trim()) as ExecEvent);
      } catch {
        /* ignore a malformed frame */
      }
    }
  }
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
  payload: { command: string; session_id?: string | null },
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

/** The footprint for one command. `allow_llm: false` gives a purely grounded answer. */
export const detectionFootprint = (
  body: {
    command?: string;
    args?: string[];
    argv?: string;
    context?: string;
    allow_llm?: boolean;
  },
  signal?: AbortSignal
) => postJSON<DetectionFootprint>("/detection/footprint", body, signal);

/** The footprint for an attack-path step (annotates its first real command). */
export const detectionFootprintStep = (
  step: AttackStep,
  allowLlm = true,
  signal?: AbortSignal
) =>
  postJSON<DetectionFootprint>(
    "/detection/footprint/step",
    { step, allow_llm: allowLlm },
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
