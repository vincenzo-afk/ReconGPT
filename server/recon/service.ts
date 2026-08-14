import { nanoid } from "nanoid";
import { invokeLLM } from "../_core/llm";
import { ENV } from "../_core/env";
import * as db from "../db";
import { modulesFor } from "./modules";
import { parseTarget } from "./target";
import type { ReconEntityInput, ReconFinding, ReconOptions, StreamEvent } from "./types";

const severityWeight = { low: 1, medium: 4, high: 7, critical: 10 } as const;
const entropy = (value: string) => `${value}`.trim().toLowerCase();

export function calculateRisk(findings: ReconFinding[]) {
  const strongest = findings.reduce((max, item) => Math.max(max, severityWeight[item.severity]), 0);
  const evidenceCount = findings.filter(item => item.severity !== "low").length;
  const score = Math.min(100, strongest * 8 + evidenceCount * 4);
  return { score, level: score >= 72 ? "critical" as const : score >= 48 ? "high" as const : score >= 20 ? "medium" as const : "low" as const };
}

function safeSummary(target: string, findings: ReconFinding[], score: number) {
  const categories = Array.from(new Set(findings.map(item => item.category)));
  const elevated = findings.filter(item => item.severity !== "low");
  return `${findings.length} verified passive-intelligence findings were collected for ${target} across ${categories.join(", ") || "available modules"}. The evidence-based exposure score is ${score}/100; ${elevated.length} finding(s) require analyst review.`;
}

type AnalystMessage = { role: "system" | "user" | "assistant"; content: string };

export async function completeAnalysis(messages: AnalystMessage[], preferredModel = "built-in") {
  const parts = preferredModel.split(":");
  const wantsExternal = parts[0] === "external" && (parts[1] === "openai" || parts[1] === "groq");
  if (wantsExternal && ENV.externalLlmApiKey) {
    const provider = parts[1];
    const model = parts.slice(2).join(":") || (provider === "groq" ? "llama-3.3-70b-versatile" : "gpt-4o-mini");
    const endpoint = provider === "groq" ? "https://api.groq.com/openai/v1/chat/completions" : "https://api.openai.com/v1/chat/completions";
    const response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${ENV.externalLlmApiKey}` }, body: JSON.stringify({ model, messages, temperature: 0.2 }), signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`Optional ${provider} analyst provider returned ${response.status}.`);
    const payload = await response.json() as { choices?: Array<{ message?: { content?: string } }> };
    const content = payload.choices?.[0]?.message?.content;
    if (content?.trim()) return content.trim();
    throw new Error("Optional analyst provider returned no content.");
  }
  const builtInModel = preferredModel.startsWith("built-in:") ? preferredModel.slice("built-in:".length) : undefined;
  const response = await invokeLLM({ model: builtInModel, messages });
  const content = response.choices?.[0]?.message?.content;
  if (typeof content !== "string" || !content.trim()) throw new Error("Built-in analyst provider returned no content.");
  return content.trim();
}

async function aiSummary(target: string, findings: ReconFinding[], score: number, preferredModel = "built-in") {
  const compact = findings.slice(0, 40).map(item => ({ category: item.category, title: item.title, severity: item.severity, summary: item.summary, data: item.data })).slice(0, 40);
  try {
    return await completeAnalysis([
        { role: "system", content: "You are ReconGPT's evidence-first OSINT analyst. Summarize only the supplied verified passive-intelligence results. Do not make claims not supported by the evidence. Do not suggest exploitation, credential attacks, phishing, or intrusive scanning. Use concise Markdown with: Executive assessment, Key findings, Analyst follow-ups, Evidence limitations." },
        { role: "user", content: JSON.stringify({ target, evidenceScore: score, findings: compact }) },
      ], preferredModel);
  } catch {
    return safeSummary(target, findings, score);
  }
}

export function graphFor(runId: string, target: ReturnType<typeof parseTarget>, findings: ReconFinding[]) {
  const byValue = new Map<string, { id: string; entity: ReconEntityInput }>();
  const relationships: Array<{ id: string; runId: string; sourceEntityId: string; targetEntityId: string; relationType: string; evidence?: string }> = [];
  const targetEntityType = target.type === "company" ? "organization" : target.type === "url" ? "url" : target.type;
  const rootEntity: ReconEntityInput = { type: targetEntityType, value: target.normalized, label: target.normalized, confidence: 100 };
  const rootKey = `${rootEntity.type}:${entropy(rootEntity.value)}`;
  const rootId = nanoid(14);
  byValue.set(rootKey, { id: rootId, entity: rootEntity });
  for (const current of findings) {
    for (const entity of current.entities || []) {
      const key = `${entity.type}:${entropy(entity.value)}`;
      if (!byValue.has(key)) byValue.set(key, { id: nanoid(14), entity });
      const targetEntity = byValue.get(key);
      if (targetEntity && targetEntity.id !== rootId) relationships.push({ id: nanoid(14), runId, sourceEntityId: rootId, targetEntityId: targetEntity.id, relationType: "observed-for", evidence: current.id });
    }
    for (const relation of current.relationships || []) {
      const source = Array.from(byValue.values()).find(item => entropy(item.entity.value) === entropy(relation.sourceValue));
      const target = Array.from(byValue.values()).find(item => entropy(item.entity.value) === entropy(relation.targetValue));
      if (source && target && source.id !== target.id) relationships.push({ id: nanoid(14), runId, sourceEntityId: source.id, targetEntityId: target.id, relationType: relation.relationType, evidence: relation.evidence });
    }
  }
  const entities = Array.from(byValue.values()).map(({ id, entity }) => ({ id, runId, entityType: entity.type, value: entity.value, label: entity.label || entity.value, confidence: entity.confidence ?? 75, metadataJson: JSON.stringify(entity.metadata || {}) }));
  return { entities, relationships };
}

type ExecuteInput = { userId: number; rawTarget: string; context: string; options: ReconOptions; emit: (event: StreamEvent) => Promise<void> | void };

export async function executeRecon({ userId, rawTarget, context, options, emit }: ExecuteInput) {
  const target = parseTarget(rawTarget);
  const runId = nanoid(14);
  const activeModules = modulesFor(target, options);
  const findings: ReconFinding[] = [];
  const send = async (type: StreamEvent["type"], message: string, moduleId?: string, data?: unknown) => {
    const event = { type, runId, moduleId, message, data, timestamp: new Date().toISOString() } as StreamEvent;
    await emit(event);
    if (type !== "run-completed") await db.appendReconEvent({ runId, moduleId: moduleId || "orchestrator", eventType: type, message, payloadJson: data ? JSON.stringify(data) : null });
  };
  await db.createReconRun({ id: runId, userId, target: target.normalized, targetType: target.type, context: context || null, status: "running" });
  await send("queued", `${activeModules.length} passive module(s) queued for ${target.normalized}.`, "orchestrator", { target, activeModules: activeModules.map(module => ({ id: module.id, label: module.label, category: module.category })) });
  for (const module of activeModules) {
    await send("started", `${module.label} is collecting public intelligence.`, module.id);
    try {
      const result = await module.execute(target, options);
      for (const notice of result.notices || []) await send("notice", notice, module.id);
      for (const item of result.findings) {
        findings.push(item);
        await send("finding", item.title, module.id, item);
      }
      await send("completed", `${module.label} completed with ${result.findings.length} finding(s).`, module.id);
    } catch (error) {
      await send("failed", `${module.label} did not return a result: ${error instanceof Error ? error.message : "unknown error"}.`, module.id);
    }
  }
  const risk = calculateRisk(findings);
  const analystSettings = await db.getAnalystSettings(userId);
  const summary = await aiSummary(target.normalized, findings, risk.score, analystSettings?.preferredModel || "built-in");
  const graph = graphFor(runId, target, findings);
  await db.saveEntitiesAndRelationships(graph.entities, graph.relationships);
  const results = { target, context, findings, entities: graph.entities, relationships: graph.relationships, risk, summary, completedAt: new Date().toISOString() };
  await db.updateReconRun(runId, { status: "completed", riskScore: risk.score, riskLevel: risk.level, summary, resultsJson: JSON.stringify(results), completedAt: new Date() });
  await send("run-completed", `Recon complete: ${findings.length} findings; evidence score ${risk.score}/100.`, "orchestrator", results);
  return { runId, ...results };
}

export function providerStatus() {
  return {
    shodan: Boolean(ENV.shodanApiKey), virustotal: Boolean(ENV.virustotalApiKey), abuseipdb: Boolean(ENV.abuseIpdbApiKey), urlscan: Boolean(ENV.urlscanApiKey), ipinfo: Boolean(ENV.ipinfoToken), externalLlm: Boolean(ENV.externalLlmApiKey), builtInAnalysis: true,
  };
}
