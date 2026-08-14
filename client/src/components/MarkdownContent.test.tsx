import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { MarkdownContent } from "./MarkdownContent";

describe("MarkdownContent", () => {
  it("renders GFM structure and suppresses raw HTML or unsafe link protocols", () => {
    const html = renderToStaticMarkup(<MarkdownContent content={"## Evidence\n\n- verified `signal`\n\n[Source](https://example.com) [unsafe](javascript:alert(1))\n\n<script>alert(1)</script>"} />);
    expect(html).toContain("<h2>Evidence</h2>");
    expect(html).toContain("<code>signal</code>");
    expect(html).toContain('href="https://example.com"');
    expect(html).not.toContain("javascript:");
    expect(html).not.toContain("<script>");
  });
});
