import { describe, expect, it } from "vitest";
import { calculateRisk, compactValue, graphFor, groundedAnalysis, providerStatus } from "./service";
import { parseTarget } from "./target";

describe("ReconGPT provider vault reporting", () => {
  it("never exposes a provider key through status metadata", () => {
    const status = providerStatus();
    expect(status).toHaveProperty("builtInAnalysis", true);
    expect(Object.values(status).every(value => typeof value === "boolean")).toBe(true);
    expect(JSON.stringify(status)).not.toMatch(/sk-|api[_-]?key|token/i);
  });
});

describe("ReconGPT evidence modeling", () => {
  it("always separates direct evidence, inference, unavailable sources, and limitations", () => {
    const summary = groundedAnalysis("## Executive assessment\nA cautious overview.", "example.com", [{ title: "MX record", category: "Domain", severity: "low", confidence: 90, sourceUrl: "https://example.com/evidence" }] as never, [{ moduleId: "archive", label: "Wayback History", category: "Historical", status: "failed", findingCount: 0, notices: [], error: "rate limited" }, { moduleId: "dns", label: "DNS posture", category: "Domain", status: "no-findings", findingCount: 0, notices: [] }] as never, 8);
    expect(summary).toContain("## Direct evidence");
    expect(summary).toContain("## Cautious interpretation");
    expect(summary).toContain("## Unavailable or incomplete sources");
    expect(summary).toContain("Wayback History");
    expect(summary).toContain("not proof of absence");
    expect(summary).toContain("## Evidence limitations");
  });

  it("bounds oversized nested public evidence before it is stored or streamed", () => {
    const source = { long: "x".repeat(9_000), rows: Array.from({ length: 120 }, (_, index) => ({ index, value: "y".repeat(100) })) };
    const compacted = compactValue(source) as { long: string; rows: unknown[] };
    expect(compacted.long).toContain("[truncated");
    expect(compacted.rows).toHaveLength(81);
    expect(JSON.stringify(compacted).length).toBeLessThan(JSON.stringify(source).length);
  });

  it("derives a bounded evidence score from verified finding severities", () => {
    expect(calculateRisk([])).toEqual({ score: 0, level: "low" });
    expect(calculateRisk([{ severity: "high" }, { severity: "medium" }] as never)).toEqual({ score: 64, level: "high" });
  });

  it("connects each discovered entity to the normalized target in the graph", () => {
    const graph = graphFor("run-123", parseTarget("example.com"), [{ id: "finding-1", entities: [{ type: "ip", value: "93.184.216.34" }] }] as never);
    expect(graph.entities).toEqual(expect.arrayContaining([expect.objectContaining({ entityType: "domain", value: "example.com" }), expect.objectContaining({ entityType: "ip", value: "93.184.216.34" })]));
    expect(graph.relationships).toEqual(expect.arrayContaining([expect.objectContaining({ relationType: "observed-for", evidence: "finding-1" })]));
  });
});
