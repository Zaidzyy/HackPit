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
  category: string;
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
};

/** One ranked search result (snippet emphasises matches with **markers**). */
export type SearchHit = {
  rank: number;
  score: number;
  id: string;
  title: string;
  category: string;
  source: string;
  tier: number | null;
  snippet: string;
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
  /** The cited KB entry — links to /entry/{entry_id}. */
  entry_id: string;
  why: string;
  /** Real commands lifted from the cited KB entry (never model-invented). */
  commands: Code[];
};

export type AttackPhase = {
  /** recon | enumeration | exploitation | privesc | post-exploitation */
  phase: string;
  label: string;
  steps: AttackStep[];
};

export type AttackPath = {
  goal: string;
  target_type: string | null;
  phases: AttackPhase[];
  /** Model that composed the path (e.g. "qwen3:8b"). */
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
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body?.detail === "string" && body.detail.trim()) {
      return body.detail;
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

/** Compose a guided attack path. Slow: the local model can take a minute+. */
export const composeAttackPath = (
  goal: string,
  target_type?: string | null,
  signal?: AbortSignal
) =>
  postJSON<AttackPath>(
    "/attack-path",
    { goal, target_type: target_type ?? null },
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
  phases: EngagementPhase[];
  model_used: string;
  provider: string;
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
