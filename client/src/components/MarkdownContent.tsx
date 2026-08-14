import React from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

type MarkdownContentProps = { content: string; className?: string };

function safeHref(value?: string) {
  return value && /^https?:\/\//i.test(value) ? value : undefined;
}

export function MarkdownContent({ content, className = "" }: MarkdownContentProps) {
  return <div className={`analyst-markdown ${className}`.trim()}>
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      skipHtml
      components={{
        a: ({ href, children }) => <a href={safeHref(href)} target="_blank" rel="noreferrer">{children}</a>,
        code: ({ className: codeClass, children }) => <code className={codeClass}>{children}</code>,
      }}
    >
      {content}
    </ReactMarkdown>
  </div>;
}
