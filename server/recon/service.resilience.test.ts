import { beforeEach, describe, expect, it, vi } from "vitest";

const { db } = vi.hoisted(() => ({ db: {
  appendReconEvent: vi.fn().mockResolvedValue(undefined),
  createReconRun: vi.fn().mockResolvedValue(undefined),
  getAnalystSettings: vi.fn().mockResolvedValue(null),
  saveEntitiesAndRelationships: vi.fn().mockRejectedValue(new Error("Simulated results payload write failure")),
  updateReconRun: vi.fn().mockResolvedValue(undefined),
} }));

vi.mock("../db", () => db);
vi.mock("../_core/llm", () => ({ invokeLLM: vi.fn().mockRejectedValue(new Error("Simulated analyst provider failure")) }));
vi.mock("./modules", () => ({
  modulesFor: () => [
    { id: "healthy-source", label: "Healthy source", category: "Test", execute: async () => ({ findings: [{ id: "test-finding", moduleId: "healthy-source", category: "Test", title: "Returned evidence", summary: "Public test evidence.", severity: "low", confidence: 90, data: {}, entities: [] }] }) },
    { id: "failed-source", label: "Failed source", category: "Test", execute: async () => { throw new Error("Simulated provider timeout"); } },
  ],
}));

import { executeRecon } from "./service";

describe("ReconGPT resilient run completion", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.appendReconEvent.mockResolvedValue(undefined);
    db.createReconRun.mockResolvedValue(undefined);
    db.getAnalystSettings.mockResolvedValue(null);
    db.saveEntitiesAndRelationships.mockRejectedValue(new Error("Simulated results payload write failure"));
    db.updateReconRun.mockResolvedValue(undefined);
  });

  it("reports a failed source, completes the run, and emits a degraded-persistence warning when storage fails", async () => {
    const events: Array<{ type: string; data?: unknown }> = [];
    await executeRecon({ userId: 1, rawTarget: "example.com", context: "Authorized test", options: { dorkIntensity: "focused" }, emit: event => { events.push(event); } });
    expect(events).toEqual(expect.arrayContaining([expect.objectContaining({ type: "failed" })]));
    const completed = events.find(event => event.type === "run-completed");
    expect(completed?.data).toEqual(expect.objectContaining({ persistence: expect.objectContaining({ status: "degraded" }), coverage: expect.arrayContaining([expect.objectContaining({ moduleId: "healthy-source", status: "completed" }), expect.objectContaining({ moduleId: "failed-source", status: "failed" })]) }));
    expect(db.updateReconRun).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ status: "completed", error: expect.stringContaining("Simulated results payload write failure") }));
  });
});
