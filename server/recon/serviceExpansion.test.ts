import { beforeEach, describe, expect, it, vi } from "vitest";

const { db } = vi.hoisted(() => ({ db: {
  appendReconEvent: vi.fn().mockResolvedValue(undefined),
  createReconRun: vi.fn().mockResolvedValue(undefined),
  getAnalystSettings: vi.fn().mockResolvedValue(null),
  saveEntitiesAndRelationships: vi.fn().mockResolvedValue(undefined),
  updateReconRun: vi.fn().mockResolvedValue(undefined),
} }));

vi.mock("../db", () => db);
vi.mock("../_core/llm", () => ({ invokeLLM: vi.fn().mockRejectedValue(new Error("No external model in deterministic test")) }));
vi.mock("./modules", () => ({
  modulesFor: () => [
    { id: "email-disclosure", label: "Email & Disclosure Posture", category: "Email Posture", execute: async () => ({ findings: [{ id: "mail-1", moduleId: "email-disclosure", category: "Email Posture", title: "MTA-STS", summary: "Public policy observed.", severity: "low", confidence: 88, sourceUrl: "https://example.co.uk/.well-known/mta-sts.txt", data: { sources: [{ name: "MTA-STS" }] }, entities: [{ type: "domain", value: "example.co.uk" }] }] }) },
    { id: "certificate-timeline", label: "Certificate Change Timeline", category: "Historical", execute: async () => ({ findings: [{ id: "cert-1", moduleId: "certificate-timeline", category: "Historical", title: "Certificate timeline", summary: "Public certificate context.", severity: "low", confidence: 80, sourceUrl: "https://crt.sh/?q=%25.example.co.uk", data: {}, entities: [{ type: "domain", value: "example.co.uk" }] }] }) },
    { id: "defensive-brand-leads", label: "Defensive Brand Leads", category: "Brand Intelligence", execute: async () => ({ findings: [{ id: "brand-1", moduleId: "defensive-brand-leads", category: "Brand Intelligence", title: "Brand lead", summary: "Manual review required.", severity: "low", confidence: 35, data: {}, entities: [{ type: "domain", value: "example.co.uk" }] }] }) },
  ],
}));

import { executeRecon } from "./service";

describe("ReconGPT authorized passive-expansion run", () => {
  beforeEach(() => vi.clearAllMocks());

  it("preserves direct observations, review leads, coverage, and graph entities for an authorized public target", async () => {
    const events: Array<{ type: string; data?: unknown }> = [];
    const completed = await executeRecon({ userId: 1, rawTarget: "example.co.uk", context: "Authorized public test target", options: { dorkIntensity: "focused" }, emit: event => { events.push(event); } });
    expect(completed.findings).toEqual(expect.arrayContaining([expect.objectContaining({ moduleId: "email-disclosure", evidenceQuality: "direct", leadStatus: "verified" }), expect.objectContaining({ moduleId: "defensive-brand-leads", evidenceQuality: "lead", leadStatus: "review" })]));
    expect(completed.coverage).toEqual(expect.arrayContaining([expect.objectContaining({ moduleId: "email-disclosure", status: "completed" }), expect.objectContaining({ moduleId: "certificate-timeline", status: "completed" }), expect.objectContaining({ moduleId: "defensive-brand-leads", status: "completed" })]));
    expect(completed.entities).toEqual(expect.arrayContaining([expect.objectContaining({ entityType: "domain", value: "example.co.uk" })]));
    expect(events).toEqual(expect.arrayContaining([expect.objectContaining({ type: "run-completed", data: expect.objectContaining({ coverage: expect.arrayContaining([expect.objectContaining({ moduleId: "defensive-brand-leads", status: "completed" })]) }) })]));
  });
});
