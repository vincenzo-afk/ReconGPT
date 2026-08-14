import { describe, expect, it } from "vitest";
import { normalizeEvidenceMetadata } from "./service";

describe("ReconGPT evidence normalization", () => {
  it("keeps analyst-review pivots separate from verified passive observations", () => {
    const lead = normalizeEvidenceMetadata({ id: "lead-1", moduleId: "public-advisory-pivots", category: "Research", title: "Advisory pivot", summary: "Manual review", severity: "low", confidence: 100, data: {} }, "2026-08-14T00:00:00.000Z");
    expect(lead.evidenceQuality).toBe("lead");
    expect(lead.leadStatus).toBe("review");
    expect(lead.sourceCount).toBe(0);
    expect(lead.limitations?.[0]).toMatch(/not verified attribution/i);
  });

  it("adds direct-source freshness, source counts, and limitations to legacy findings", () => {
    const direct = normalizeEvidenceMetadata({ id: "direct-1", moduleId: "dns-posture", category: "Domain", title: "DNS", summary: "Observation", severity: "low", confidence: 90, sourceUrl: "https://dns.google/resolve", data: { sources: [{ name: "DNS" }, { name: "RDAP" }] } }, "2026-08-14T00:00:00.000Z");
    expect(direct.evidenceQuality).toBe("direct");
    expect(direct.leadStatus).toBe("verified");
    expect(direct.sourceCount).toBe(2);
    expect(direct.collectedAt).toBe("2026-08-14T00:00:00.000Z");
    expect(direct.limitations?.[0]).toMatch(/point-in-time/i);
  });
});
