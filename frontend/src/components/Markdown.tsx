"use client";

import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeSanitize from "rehype-sanitize";
import { CopyButton } from "./CopyButton";
import { imageUrl } from "@/lib/api";

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** A fenced/indented code block rendered in the theme with a copy button. */
function MdCodeBlock({ lang, text }: { lang: string; text: string }) {
  return (
    <div className="hp-code">
      <div className="hp-code-bar">
        <span className="hp-code-lang">{lang}</span>
        <CopyButton text={text} />
      </div>
      <pre className="hp-code-pre">
        <code>{text}</code>
      </pre>
    </div>
  );
}

const components: Components = {
  // Our code block renders its own <pre>; unwrap react-markdown's to avoid nesting.
  pre: ({ children }) => <>{children}</>,
  code({ className, children }) {
    const text = String(children ?? "").replace(/\n$/, "");
    const isBlock = /language-/.test(className ?? "") || text.includes("\n");
    if (!isBlock) {
      return <code className="hp-md-code-inline">{children}</code>;
    }
    const lang = /language-(\w+)/.exec(className ?? "")?.[1] ?? "sh";
    return <MdCodeBlock lang={lang} text={text} />;
  },
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  ),
  // Route note-relative image srcs through the sandboxed backend route; hide
  // gracefully if the file can't be served rather than showing a broken icon.
  img: ({ src, alt }) => {
    if (typeof src !== "string" || !src) return null;
    const remote = /^(https?:|data:)/i.test(src);
    const url = remote ? src : imageUrl(safeDecode(src));
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img
        className="hp-md-img"
        src={url}
        alt={alt || ""}
        loading="lazy"
        onError={(e) => {
          e.currentTarget.style.display = "none";
        }}
      />
    );
  },
};

/**
 * Lightweight, sanitized markdown renderer styled to the HackPit theme.
 * Used for the stepless entries that fall back to `body_md`.
 */
export function Markdown({ source }: { source: string }) {
  return (
    <div className="hp-md">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeSanitize]}
        components={components}
      >
        {source}
      </ReactMarkdown>
    </div>
  );
}
