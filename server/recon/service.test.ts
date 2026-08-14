import { describe, expect, it } from "vitest";
import { calculateRisk, graphFor, providerStatus } from "./service";
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
