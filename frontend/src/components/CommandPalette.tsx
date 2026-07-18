"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useRouter } from "next/navigation";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { ApiError, search, type SearchResponse } from "@/lib/api";
import { OPEN_PALETTE_EVENT } from "@/lib/paletteBus";
import { useReducedMotion } from "@/lib/useReducedMotion";

const MIN_QUERY = 2;
const DEBOUNCE_MS = 150;

function prettyCat(slug: string) {
  return slug.replace(/-/g, " ");
}

/** Render a backend snippet, emphasising **matched** terms in amber. */
function renderSnippet(snippet: string): ReactNode[] {
  return snippet.split("**").map((part, i) =>
    i % 2 === 1 && part ? (
      <mark key={i} className="hp-hit">
        {part}
      </mark>
    ) : (
      <span key={i}>{part}</span>
    )
  );
}

/**
 * Global ⌘K / Ctrl+K command palette wired to GET /search. Mounted once at the
 * app root so it works on every route. Debounced hybrid search, full keyboard
 * navigation, and a transparent footer showing whether search ran hybrid or
 * fell back to lexical (Ollama offline).
 */
export function CommandPalette() {
  const router = useRouter();
  const reduced = useReducedMotion();

  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [resp, setResp] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState(0);

  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const lastFocused = useRef<HTMLElement | null>(null);
  const openRef = useRef(false);

  const open = useCallback(() => {
    if (openRef.current) return;
    lastFocused.current = document.activeElement as HTMLElement | null;
    openRef.current = true;
    setQuery("");
    setResp(null);
    setError(null);
    setSelected(0);
    setIsOpen(true);
  }, []);

  const close = useCallback((restoreFocus = true) => {
    if (!openRef.current) return;
    openRef.current = false;
    setIsOpen(false);
    if (restoreFocus) {
      requestAnimationFrame(() => lastFocused.current?.focus?.());
    }
  }, []);

  // Global ⌘K / Ctrl+K toggle + open-event from the TopBar affordance.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        openRef.current ? close() : open();
      }
    };
    const onOpenEvent = () => open();
    window.addEventListener("keydown", onKey);
    window.addEventListener(OPEN_PALETTE_EVENT, onOpenEvent);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener(OPEN_PALETTE_EVENT, onOpenEvent);
    };
  }, [open, close]);

  // Focus the input + lock body scroll while open.
  useEffect(() => {
    if (!isOpen) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const id = requestAnimationFrame(() => inputRef.current?.focus());
    return () => {
      document.body.style.overflow = prevOverflow;
      cancelAnimationFrame(id);
    };
  }, [isOpen]);

  // Debounced search.
  useEffect(() => {
    if (!isOpen) return;
    const q = query.trim();
    if (q.length < MIN_QUERY) {
      setResp(null);
      setError(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    const ctrl = new AbortController();
    const timer = setTimeout(() => {
      search(q, { mode: "hybrid", top: 20 }, ctrl.signal)
        .then((r) => {
          setResp(r);
          setError(null);
          setLoading(false);
          setSelected(0);
        })
        .catch((err: unknown) => {
          if (ctrl.signal.aborted) return;
          setResp(null);
          setLoading(false);
          setError(
            err instanceof ApiError ? err.message : "Search failed."
          );
        });
    }, DEBOUNCE_MS);
    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [query, isOpen]);

  // Keep the selected row in view during keyboard nav.
  useEffect(() => {
    itemRefs.current[selected]?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  const results = resp?.results ?? [];

  const openEntry = useCallback(
    (id: string) => {
      close(false);
      router.push(`/entry/${id}`);
    },
    [close, router]
  );

  const onInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelected((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelected((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const hit = results[selected];
      if (hit) openEntry(hit.id);
    } else if (e.key === "Escape") {
      e.preventDefault();
      close();
    }
  };

  const q = query.trim();
  const modeLabel = resp
    ? resp.fell_back
      ? "lexical · fallback (Ollama offline)"
      : resp.mode
    : null;

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className="hp-cmdk-overlay"
          role="dialog"
          aria-modal="true"
          aria-label="Search techniques"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: reduced ? 0 : 0.15 }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) close();
          }}
        >
          <motion.div
            className="hp-cmdk-panel"
            initial={{ opacity: 0, y: reduced ? 0 : -10, scale: reduced ? 1 : 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: reduced ? 0 : -10, scale: reduced ? 1 : 0.98 }}
            transition={{ duration: reduced ? 0 : 0.18, ease: "easeOut" }}
          >
            <div className="hp-cmdk-inputrow">
              <span className="hp-cmdk-prompt" aria-hidden>
                ⌕
              </span>
              <input
                ref={inputRef}
                className="hp-cmdk-input"
                placeholder="Search techniques, tools, workflows…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={onInputKeyDown}
                spellCheck={false}
                autoComplete="off"
                aria-label="Search query"
              />
              <kbd className="hp-cmdk-esc">esc</kbd>
            </div>

            <div className="hp-cmdk-results" ref={listRef}>
              {q.length < MIN_QUERY && (
                <div className="hp-cmdk-hint-empty">
                  Start typing to search the knowledge base.
                </div>
              )}

              {q.length >= MIN_QUERY && loading && !resp && (
                <div className="hp-cmdk-hint-empty">searching…</div>
              )}

              {q.length >= MIN_QUERY && error && (
                <div className="hp-cmdk-hint-empty hp-note-err">{error}</div>
              )}

              {q.length >= MIN_QUERY &&
                !loading &&
                !error &&
                resp &&
                results.length === 0 && (
                  <div className="hp-cmdk-hint-empty">
                    no matches for “{q}”
                  </div>
                )}

              {results.map((hit, i) => (
                <button
                  key={hit.id}
                  type="button"
                  ref={(el) => {
                    itemRefs.current[i] = el;
                  }}
                  className={`hp-cmdk-item${i === selected ? " is-sel" : ""}`}
                  onMouseMove={() => setSelected(i)}
                  onClick={() => openEntry(hit.id)}
                >
                  <div className="hp-cmdk-item-head">
                    <span className="hp-cmdk-item-title">{hit.title}</span>
                    <span className="hp-cmdk-item-meta">
                      <span className="hp-cmdk-cat">{prettyCat(hit.category)}</span>
                      <span
                        className={`hp-badge-src${
                          hit.tier === 1 ? " is-notes" : ""
                        }`}
                      >
                        {hit.tier === 1 ? "notes" : hit.source}
                      </span>
                    </span>
                  </div>
                  {hit.snippet && (
                    <div className="hp-cmdk-snip">
                      {renderSnippet(hit.snippet)}
                    </div>
                  )}
                </button>
              ))}
            </div>

            <div className="hp-cmdk-foot">
              <span className="hp-cmdk-hints">
                <kbd>↑</kbd>
                <kbd>↓</kbd> navigate&nbsp;·&nbsp;<kbd>↵</kbd> open&nbsp;·&nbsp;
                <kbd>esc</kbd> close
              </span>
              {modeLabel && (
                <span className="hp-cmdk-mode">
                  <span
                    className={`hp-cmdk-dot${resp?.fell_back ? " is-fallback" : ""}`}
                  />
                  {modeLabel}
                  {resp ? ` · ${resp.count}` : ""}
                </span>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
