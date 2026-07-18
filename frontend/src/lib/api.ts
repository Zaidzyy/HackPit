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

export const getStats = (signal?: AbortSignal) =>
  getJSON<Stats>("/stats", signal);

export const getCategories = (signal?: AbortSignal) =>
  getJSON<Category[]>("/categories", signal);

export const getCategory = (slug: string, signal?: AbortSignal) =>
  getJSON<EntrySummary[]>(`/categories/${encodeURIComponent(slug)}`, signal);

export const getEntry = (id: string, signal?: AbortSignal) =>
  getJSON<Entry>(`/entry/${encodeURIComponent(id)}`, signal);
