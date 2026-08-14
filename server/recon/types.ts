export const TARGET_TYPES = ["domain", "ip", "email", "username", "company", "url", "phone", "asn"] as const;
export type TargetType = (typeof TARGET_TYPES)[number];

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type EntityType = "domain" | "subdomain" | "ip" | "email" | "username" | "organization" | "url" | "certificate" | "asn" | "phone";

export type ReconTarget = {
  raw: string;
  normalized: string;
  type: TargetType;
  hostname?: string;
  domain?: string;
};

export type ReconEntityInput = {
  type: EntityType;
  value: string;
  label?: string;
  confidence?: number;
  metadata?: Record<string, unknown>;
};

export type RelationshipInput = {
  sourceValue: string;
  targetValue: string;
  relationType: string;
  evidence?: string;
};

export type ReconFinding = {
  id: string;
  moduleId: string;
  category: string;
  title: string;
  summary: string;
  severity: RiskLevel;
  confidence: number;
  sourceUrl?: string;
  data: Record<string, unknown>;
  entities?: ReconEntityInput[];
  relationships?: RelationshipInput[];
};

export type ModuleResult = {
  findings: ReconFinding[];
  notices?: string[];
};

export type ModuleCoverage = {
  moduleId: string;
  label: string;
  category: string;
  status: "completed" | "no-findings" | "failed";
  findingCount: number;
  notices: string[];
  error?: string;
};

export type ModuleDefinition = {
  id: string;
  label: string;
  category: string;
  appliesTo: TargetType[];
  requiresKey?: "shodan" | "virustotal" | "abuseipdb" | "urlscan" | "ipinfo";
  execute: (target: ReconTarget, options: ReconOptions) => Promise<ModuleResult>;
};

export type ReconOptions = {
  dorkIntensity: "focused" | "balanced" | "deep";
  enabledModules?: string[];
};

export type StreamEvent = {
  type: "queued" | "started" | "finding" | "completed" | "failed" | "notice" | "run-completed";
  runId: string;
  moduleId?: string;
  message: string;
  data?: unknown;
  timestamp: string;
};
