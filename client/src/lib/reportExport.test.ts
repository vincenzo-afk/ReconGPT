import { describe, expect, it } from "vitest";
import { markdownReport, printableHtmlReport } from "./reportExport";

const result = {
  target: { normalized: "example.com", type: "domain" },
  completedAt: "2026-08-14T12:00:00.000Z",
  risk: { score: 24, level: "medium" },
  summary: "Evidence-based summary.",
  findings: [{ category: "Domain", title: "DNS posture", severity: "medium", summary: "A verified finding.", sourceUrl: "https://example.com/?a=<unsafe>" }],
};

describe("ReconGPT report export", () => {
  it("serializes target, risk, findings, and limitations as Markdown", () => {
    const markdown = markdownReport(result);
    expect(markdown).toContain("# ReconGPT Intelligence Report");
    expect(markdown).toContain("example.com");
    expect(markdown).toContain("24/100");
    expect(markdown).toContain("Methodology and limitations");
  });

  it("escapes untrusted report content in printable HTML", () => {
    const html = printableHtmlReport(result);
    expect(html).toContain("ReconGPT Intelligence Report");
    expect(html).toContain("&lt;unsafe&gt;");
    expect(html).not.toContain("<unsafe>");
  });
});
