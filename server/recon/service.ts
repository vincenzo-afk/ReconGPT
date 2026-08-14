import { nanoid } from "nanoid";
import { invokeLLM } from "../_core/llm";
import { ENV } from "../_core/env";
import * as db from "../db";
import { modulesFor } from "./modules";
import { parseTarget } from "./target";
import type { ModuleCoverage, ReconEntityInput, ReconFinding, ReconOptions, StreamEvent } from "./types";

const severityWeight = { low: 1, medium: 4, high: 7, critical: 10 } as const;
const entropy = (value: string) => `${value}`.trim().toLowerCase();

export function calculateRisk(findings: ReconFinding[]) {
  const strongest = findings.reduce((max, item) => Math.max(max, severityWeight[item.severity]), 0);
  const evidenceCount = findings.filter(item => item.severity !== "low").length;
  const score = Math.min(100, strongest * 8 + evidenceCount * 4);
  return { score, level: score >= 72 ? "critical" as const : score >= 48 ? "high" as const : score >= 20 ? "medium" as const : "low" as const };
}

function metadataSourceCount(finding: ReconFinding) {
  const listed = Array.isArray(finding.data.sources) ? finding.data.sources.length : 0;
  const linked = finding.sourceUrl ? 1 : 0;
  return Math.max(listed, linked, finding.sourceCount || 0);
}

export function normalizeEvidenceMetadata(finding: ReconFinding, collectedAt = new Date().toISOString()): ReconFinding {
  const leadModule = ["research-dorks", "exposure-research", "public-advisory-pivots", "defensive-brand-leads", "phone-research", "corporate-research", "asn-research"].includes(finding.moduleId);
  const evidenceQuality = finding.evidenceQuality || (leadModule ? "lead" : finding.sourceUrl ? "direct" : "context");
  const defaultLimitation = evidenceQuality === "lead"
    ? "This is an analyst-review lead, not verified attribution, exposure, ownership, or exploitability."
    : "This is a passive, point-in-time public-source observation and may be incomplete, stale, rate-limited, or scoped differently by the source.";
  return {
    ...finding,
    evidenceQuality,
    leadStatus: finding.leadStatus || (evidenceQuality === "lead" ? "review" : "verified"),
    collectedAt: finding.collectedAt || collectedAt,
    sourceCount: metadataSourceCount(finding),
    limitations: finding.limitations?.length ? finding.limitations : [defaultLimitation],
  };
}

function safeSummary(target: string, findings: ReconFinding[], score: number) {
  const categories = Array.from(new Set(findings.map(item => item.category)));
  const elevated = findings.filter(item => item.severity !== "low");
  return `${findings.length} verified passive-intelligence findings were collected for ${target} across ${categories.join(", ") || "available modules"}. The evidence-based exposure score is ${score}/100; ${elevated.length} finding(s) require analyst review.`;
}

export function groundedAnalysis(draft: string, target: string, findings: ReconFinding[], coverage: ModuleCoverage[], score: number) {
  const directEvidence = findings.slice(0, 12).map(item => `- **${item.title}** (${item.category}; ${item.evidenceQuality || "context"}; ${item.leadStatus || "verified"}; ${item.confidence}% confidence)${item.sourceUrl ? ` — ${item.sourceUrl}` : ""}`).join("\n") || "- No verified passive evidence records were returned.";
  const unavailable = coverage.filter(item => item.status === "failed").map(item => `- **${item.label}:** ${item.error || "source unavailable"}`).join("\n") || "- No selected source reported an execution failure.";
  const noResult = coverage.filter(item => item.status === "no-findings").map(item => `- **${item.label}:** no evidence returned; this is not proof of absence.`).join("\n") || "- No selected source returned an empty result set.";
  const interpretation = findings.length ? `The ${score}/100 evidence score reflects the returned public records only. Patterns across independently sourced findings are analyst leads, not proof of ownership, intent, compromise, or exploitability.` : `No positive evidence was returned. This does not establish that ${target} is clean or that relevant public records do not exist.`;
  return `${draft.trim()}\n\n## Direct evidence\n${directEvidence}\n\n## Cautious interpretation\n${interpretation}\n\n## Unavailable or incomplete sources\n${unavailable}\n${noResult}\n\n## Evidence limitations\nResults are passive, point-in-time public-source observations. They may be incomplete, stale, rate-limited, scoped differently by a provider, or unrelated to the authorized asset. Independently verify ownership and authorization before acting.`;
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

async function aiSummary(target: string, findings: ReconFinding[], score: number, coverage: ModuleCoverage[], preferredModel = "built-in") {
  const compact = findings.slice(0, 40).map(item => ({ moduleId: item.moduleId, category: item.category, title: item.title, severity: item.severity, confidence: item.confidence, evidenceQuality: item.evidenceQuality, leadStatus: item.leadStatus, sourceCount: item.sourceCount, collectedAt: item.collectedAt, limitations: item.limitations, summary: item.summary, sourceUrl: item.sourceUrl, data: compactValue(item.data) }));
  let draft: string;
  try {
    draft = await completeAnalysis([
        { role: "system", content: "You are ReconGPT's evidence-first OSINT analyst. Use only the supplied passive results. Never claim a source was searched, a fact is verified, or an absence is meaningful unless the coverage ledger supports it. Preserve each record's evidenceQuality and leadStatus: review leads are not verified findings. Separate direct evidence from cautious inference. Name sources with direct evidence, explicitly list unavailable or failed modules, and treat no-findings as unknown rather than clean. Do not suggest exploitation, credential attacks, phishing, or intrusive scanning. Use concise Markdown sections: Executive assessment, Direct evidence, Coverage and gaps, Analyst follow-ups, Evidence limitations." },
        { role: "user", content: JSON.stringify({ target, evidenceScore: score, coverage, findings: compact }) },
      ], preferredModel);
  } catch {
    draft = safeSummary(target, findings, score);
  }
  return groundedAnalysis(draft, target, findings, coverage, score);
}

export function compactValue(value: unknown, depth = 0): unknown {
  if (typeof value === "string") return value.length > 4_000 ? `${value.slice(0, 4_000)}… [truncated ${value.length - 4_000} characters]` : value;
  if (value === null || typeof value !== "object") return value;
  if (depth >= 4) return "[nested evidence truncated]";
  if (Array.isArray(value)) {
    const limit = 80;
    const items = value.slice(0, limit).map(item => compactValue(item, depth + 1));
    return value.length > limit ? [...items, `[${value.length - limit} additional item(s) omitted]`] : items;
  }
  const entries = Object.entries(value as Record<string, unknown>);
  const limit = 60;
  const compacted = Object.fromEntries(entries.slice(0, limit).map(([key, item]) => [key, compactValue(item, depth + 1)])) as Record<string, unknown>;
  if (entries.length > limit) compacted._truncatedKeys = `${entries.length - limit} additional key(s) omitted`;
  return compacted;
}

export function compactFinding(finding: ReconFinding): ReconFinding {
  return { ...finding, data: compactValue(finding.data) as Record<string, unknown>, entities: (finding.entities || []).slice(0, 250).map(entity => ({ ...entity, metadata: compactValue(entity.metadata || {}) as Record<string, unknown> })), relationships: (finding.relationships || []).slice(0, 500) };
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
  const coverage: ModuleCoverage[] = [];
  const send = async (type: StreamEvent["type"], message: string, moduleId?: string, data?: unknown) => {
    const event = { type, runId, moduleId, message, data, timestamp: new Date().toISOString() } as StreamEvent;
    await emit(event);
    if (type !== "run-completed") {
      try {
        await db.appendReconEvent({ runId, moduleId: moduleId || "orchestrator", eventType: type, message, payloadJson: data ? JSON.stringify(compactValue(data)) : null });
      } catch (error) {
        console.error("[ReconGPT] Event persistence unavailable:", error);
      }
    }
  };
  await db.createReconRun({ id: runId, userId, target: target.normalized, targetType: target.type, context: context || null, status: "running" });
  await send("queued", `${activeModules.length} passive module(s) queued for ${target.normalized}.`, "orchestrator", { target, activeModules: activeModules.map(module => ({ id: module.id, label: module.label, category: module.category })) });
  let nextModule = 0;
  const runNextModule = async () => {
    while (nextModule < activeModules.length) {
      const module = activeModules[nextModule++];
      if (!module) return;
      await send("started", `${module.label} is collecting public intelligence.`, module.id);
      try {
        const result = await module.execute(target, options);
        for (const notice of result.notices || []) await send("notice", notice, module.id);
        for (const item of result.findings) {
          const normalizedFinding = normalizeEvidenceMetadata(item);
          findings.push(normalizedFinding);
          await send("finding", normalizedFinding.title, module.id, normalizedFinding);
        }
        coverage.push({ moduleId: module.id, label: module.label, category: module.category, status: result.findings.length ? "completed" : "no-findings", findingCount: result.findings.length, notices: result.notices || [] });
        await send("completed", `${module.label} completed with ${result.findings.length} finding(s).`, module.id);
      } catch (error) {
        const message = error instanceof Error ? error.message : "unknown error";
        coverage.push({ moduleId: module.id, label: module.label, category: module.category, status: "failed", findingCount: 0, notices: [], error: message });
        await send("failed", `${module.label} did not return a result: ${message}.`, module.id);
      }
    }
  };
  const workerCount = Math.min(4, Math.max(1, activeModules.length));
  await Promise.all(Array.from({ length: workerCount }, () => runNextModule()));
  const risk = calculateRisk(findings);
  const analystSettings = await db.getAnalystSettings(userId);
  const summary = await aiSummary(target.normalized, findings, risk.score, coverage, analystSettings?.preferredModel || "built-in");
  const graph = graphFor(runId, target, findings);
  const completedAt = new Date().toISOString();
  const results = { target, context, findings, entities: graph.entities, relationships: graph.relationships, risk, summary, coverage, completedAt };
  const persistableResults = { ...results, findings: findings.map(compactFinding), entities: graph.entities.map(entity => ({ ...entity, metadataJson: JSON.stringify(compactValue(JSON.parse(entity.metadataJson || "{}"))) })) };
  let persistence = { status: "saved" as "saved" | "degraded", warning: undefined as string | undefined };
  try {
    await db.saveEntitiesAndRelationships(graph.entities, graph.relationships);
    await db.updateReconRun(runId, { status: "completed", riskScore: risk.score, riskLevel: risk.level, summary, resultsJson: JSON.stringify(persistableResults), completedAt: new Date() });
  } catch (error) {
    const warning = error instanceof Error ? error.message : "Unable to persist the complete run payload.";
    persistence = { status: "degraded", warning };
    try {
      await db.updateReconRun(runId, { status: "completed", riskScore: risk.score, riskLevel: risk.level, summary: safeSummary(target.normalized, findings, risk.score), error: warning.slice(0, 8_000), completedAt: new Date() });
    } catch (fallbackError) {
      console.error("[ReconGPT] Run completion fallback failed:", fallbackError);
    }
  }
  await send("run-completed", `Recon complete: ${findings.length} findings; evidence score ${risk.score}/100.${persistence.status === "degraded" ? " Results were delivered live, but history persistence needs attention." : ""}`, "orchestrator", { runId, target, risk, summary, coverage, persistence, completedAt });
  return { runId, ...results };
}

export function providerStatus() {
  return {
    shodan: Boolean(ENV.shodanApiKey), virustotal: Boolean(ENV.virustotalApiKey), abuseipdb: Boolean(ENV.abuseIpdbApiKey), urlscan: Boolean(ENV.urlscanApiKey), ipinfo: Boolean(ENV.ipinfoToken), externalLlm: Boolean(ENV.externalLlmApiKey), builtInAnalysis: true,
  };
}
