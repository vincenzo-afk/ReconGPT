import { describe, expect, it } from "vitest";
import { markdownReport, printableHtmlReport } from "./reportExport";

const result = {
  target: { normalized: "example.com", type: "domain" },
  completedAt: "2026-08-14T12:00:00.000Z",
  risk: { score: 24, level: "medium" },
  summary: "Evidence-based summary.",
  findings: [{ category: "Domain", title: "DNS posture", severity: "medium", summary: "A verified finding.", sourceUrl: "https://example.com/?a=<unsafe>" }],
  coverage: [{ moduleId: "archive", label: "Wayback History", category: "Historical", status: "no-findings" as const, findingCount: 0, notices: ["No archived URL was returned."] }, { moduleId: "reputation", label: "Provider Reputation", category: "Threat Intelligence", status: "failed" as const, findingCount: 0, notices: [], error: "Provider timeout" }],
  persistence: { status: "degraded" as const, warning: "History write deferred." },
};

describe("ReconGPT report export", () => {
  it("serializes target, risk, findings, coverage gaps, and limitations as Markdown", () => {
    const markdown = markdownReport(result);
    expect(markdown).toContain("# ReconGPT Intelligence Report");
    expect(markdown).toContain("example.com");
    expect(markdown).toContain("24/100");
    expect(markdown).toContain("Source coverage and limitations");
    expect(markdown).toContain("Provider timeout");
    expect(markdown).toContain("Persistence warning");
    expect(markdown).toContain("Methodology and limitations");
  });

  it("escapes untrusted report content in printable HTML", () => {
    const html = printableHtmlReport(result);
    expect(html).toContain("ReconGPT Intelligence Report");
    expect(html).toContain("Source coverage and limitations");
    expect(html).toContain("History write deferred.");
    expect(html).toContain("&lt;unsafe&gt;");
    expect(html).not.toContain("<unsafe>");
  });
});
