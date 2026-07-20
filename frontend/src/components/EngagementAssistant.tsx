"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Markdown } from "./Markdown";
import { LLMSettingsModal } from "./LLMSettingsModal";
import {
  ApiError,
  getLLMConfig,
  sendChat,
  type ChatTurn,
  type LLMConfig,
} from "@/lib/api";
import { sourceTint } from "@/lib/source";
import { useReducedMotion } from "@/lib/useReducedMotion";

/** Prefill-only prompts to get a tester moving. */
const SUGGESTIONS = [
  "what's my next move?",
  "suggest an alternative",
  "what if this step failed?",
];

/**
 * The engagement assistant — a session-aware, KB-grounded chat in a collapsible
 * right-side drawer. Collapsed it's a slim "Assistant" tab; expanded it's a chat
 * panel beside the steps. Conversation is persisted server-side (loaded via the
 * session's `chat_history`), so it survives a reload.
 */
export function EngagementAssistant({
  sessionId,
  initialHistory,
}: {
  sessionId: string;
  initialHistory: ChatTurn[];
}) {
  const reduced = useReducedMotion();

  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatTurn[]>(initialHistory);
  const [input, setInput] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [config, setConfig] = useState<LLMConfig | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const ctrlRef = useRef<AbortController | null>(null);

  // Re-seed from the persisted history when the session finishes loading.
  useEffect(() => setMessages(initialHistory), [initialHistory]);

  // Model info for the "answered by …" line + the gear's default provider.
  useEffect(() => {
    const ctrl = new AbortController();
    getLLMConfig(ctrl.signal)
      .then(setConfig)
      .catch(() => setConfig(null));
    return () => ctrl.abort();
  }, []);

  useEffect(() => () => ctrlRef.current?.abort(), []);

  // Keep the transcript pinned to the newest message while it grows.
  useEffect(() => {
    if (open && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, pending, open]);

  function send(text?: string) {
    const msg = (text ?? input).trim();
    if (!msg || pending) return;

    const userTurn: ChatTurn = {
      role: "user",
      content: msg,
      ts: new Date().toISOString(),
    };
    setMessages((m) => [...m, userTurn]);
    setInput("");
    setPending(true);
    setError(null);

    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;

    sendChat(sessionId, msg, ctrl.signal)
      .then((r) => {
        if (ctrl.signal.aborted) return;
        setMessages((m) => [
          ...m,
          {
            role: "assistant",
            content: r.reply,
            ts: r.ts,
            cited_entry_ids: r.cited_entry_ids,
          },
        ]);
        setPending(false);
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        setPending(false);
        // roll the optimistic user turn back so it can be re-sent
        setMessages((m) => m.filter((t) => t !== userTurn));
        setInput(msg);
        setError(
          err instanceof ApiError
            ? err.message
            : "The assistant couldn’t reply. Is the model running?"
        );
      });
  }

  function prefill(text: string) {
    setInput(text);
    inputRef.current?.focus();
  }

  const providerLabel =
    config?.provider === "ollama" ? "local" : (config?.provider ?? "");
  const empty = messages.length === 0;

  return (
    <>
      {/* collapsed: slim tab on the right edge */}
      {!open && (
        <button
          type="button"
          className="hp-asst-tab"
          onClick={() => setOpen(true)}
          aria-label="Open the engagement assistant"
        >
          <span className="hp-asst-tab-dot" aria-hidden />
          <span className="hp-asst-tab-label">Assistant</span>
        </button>
      )}

      <AnimatePresence>
        {open && (
          <motion.aside
            className="hp-asst"
            aria-label="Engagement assistant"
            initial={{ x: reduced ? 0 : "100%", opacity: reduced ? 0 : 1 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: reduced ? 0 : "100%", opacity: reduced ? 0 : 1 }}
            transition={{ duration: reduced ? 0.12 : 0.24, ease: "easeOut" }}
          >
            <header className="hp-asst-head">
              <div className="hp-asst-head-titles">
                <span className="hp-asst-kicker">engagement</span>
                <h2 className="hp-asst-title">Assistant</h2>
              </div>
              <button
                type="button"
                className="hp-asst-collapse"
                onClick={() => setOpen(false)}
                aria-label="Collapse the assistant"
              >
                ›
              </button>
            </header>

            <div className="hp-asst-scroll" ref={scrollRef}>
              {empty ? (
                <div className="hp-asst-empty">
                  <p className="hp-asst-empty-lead">
                    Ask about this engagement. I read your goal, the steps you’ve
                    checked, and the output you pasted — and answer grounded in
                    your knowledge base.
                  </p>
                  <div className="hp-asst-suggests">
                    {SUGGESTIONS.map((s) => (
                      <button
                        key={s}
                        type="button"
                        className="hp-asst-suggest"
                        onClick={() => prefill(s)}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <ul className="hp-asst-msgs">
                  {messages.map((m, i) => (
                    <li
                      key={`${m.ts}-${i}`}
                      className={`hp-asst-msg hp-asst-msg-${m.role}`}
                    >
                      {m.role === "assistant" ? (
                        <div className="hp-asst-bubble hp-asst-bubble-ai">
                          <Markdown source={m.content} />
                          {m.cited_entry_ids &&
                            m.cited_entry_ids.length > 0 && (
                              <div className="hp-asst-cites">
                                <span className="hp-asst-cites-label">
                                  techniques
                                </span>
                                {m.cited_entry_ids.map((id) => (
                                  <Link
                                    key={id}
                                    href={`/entry/${encodeURIComponent(id)}`}
                                    className="hp-asst-cite"
                                    style={{
                                      ["--st" as string]: sourceTint(id),
                                    }}
                                  >
                                    <span
                                      className="hp-asst-cite-ic"
                                      aria-hidden
                                    >
                                      ⧉
                                    </span>
                                    {id}
                                  </Link>
                                ))}
                              </div>
                            )}
                        </div>
                      ) : (
                        <div className="hp-asst-bubble hp-asst-bubble-user">
                          {m.content}
                        </div>
                      )}
                    </li>
                  ))}

                  {pending && (
                    <li className="hp-asst-msg hp-asst-msg-assistant">
                      <div className="hp-asst-bubble hp-asst-bubble-ai hp-asst-thinking">
                        <span className="hp-asst-think-dots" aria-hidden>
                          <i />
                          <i />
                          <i />
                        </span>
                        <span className="hp-asst-think-txt">
                          thinking… the local model can take a moment
                        </span>
                      </div>
                    </li>
                  )}
                </ul>
              )}

              {error && <p className="hp-asst-error">{error}</p>}
            </div>

            <div className="hp-asst-foot">
              {!empty && (
                <div className="hp-asst-suggests hp-asst-suggests-inline">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      type="button"
                      className="hp-asst-suggest"
                      onClick={() => prefill(s)}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              )}

              <div className="hp-asst-inputrow">
                <textarea
                  ref={inputRef}
                  className="hp-asst-input"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      send();
                    }
                  }}
                  placeholder="Ask the assistant… (Enter to send, Shift+Enter for a newline)"
                  spellCheck={false}
                  rows={2}
                  disabled={pending}
                />
                <button
                  type="button"
                  className="hp-asst-send"
                  onClick={() => send()}
                  disabled={pending || !input.trim()}
                  aria-label="Send"
                >
                  {pending ? "…" : "↑"}
                </button>
              </div>

              <div className="hp-asst-byline">
                <span className="hp-asst-model">
                  {config ? (
                    <>
                      answered by <b>{config.model}</b>
                      <span className="hp-asst-local"> · {providerLabel}</span>
                    </>
                  ) : (
                    <>grounded in your knowledge base</>
                  )}
                </span>
                <button
                  type="button"
                  className="hp-asst-gear"
                  aria-label="LLM settings"
                  onClick={() => setSettingsOpen(true)}
                >
                  ⚙
                </button>
              </div>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>

      <LLMSettingsModal
        open={settingsOpen}
        config={config}
        onClose={() => setSettingsOpen(false)}
        onSaved={(c) => setConfig(c)}
      />
    </>
  );
}
