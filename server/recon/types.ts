export const TARGET_TYPES = ["domain", "ip", "email", "username", "company", "url", "phone", "asn"] as const;
export type TargetType = (typeof TARGET_TYPES)[number];

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type EntityType = "domain" | "subdomain" | "ip" | "email" | "username" | "organization" | "url" | "certificate" | "asn" | "phone" | "social_profile" | "media" | "location_signal" | "community";
export type EvidenceQuality = "direct" | "corroborated" | "context" | "lead";
export type LeadStatus = "verified" | "review" | "unverified";
export type DataSensitivity = "public" | "contact" | "location" | "community";
export type ConsentBasis = "public-source" | "target-authorization" | "email-ownership-confirmed" | "media-authorization-confirmed" | "community-admin-confirmed";
export type RetentionClass = "standard" | "redacted" | "ephemeral";
export type IdentityConsent = { targetAuthorization?: boolean; emailOwnershipConfirmed?: boolean; mediaAuthorizationConfirmed?: boolean; communityAdminConfirmed?: boolean };
export type CommunityProvider = "discord" | "telegram";
export type CommunityScope = { provider: CommunityProvider; scopeId: string; label: string };
export type CommunityAuditEntry = { at: string; actorUserId: number; action: "configured" | "paused" | "resumed" | "purged"; scopeCount: number };
export type CommunityControls = { connectorEnabled: boolean; paused: boolean; retentionDays: number; scopes: CommunityScope[]; audit: CommunityAuditEntry[]; lastPurgeAt?: string };

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
  evidenceQuality?: EvidenceQuality;
  leadStatus?: LeadStatus;
  collectedAt?: string;
  sourceCount?: number;
  limitations?: string[];
  dataSensitivity?: DataSensitivity;
  consentBasis?: ConsentBasis;
  retentionClass?: RetentionClass;
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
  consent?: IdentityConsent;
  communityControls?: CommunityControls;
};

export type StreamEvent = {
  type: "queued" | "started" | "finding" | "completed" | "failed" | "notice" | "run-completed";
  runId: string;
  moduleId?: string;
  message: string;
  data?: unknown;
  timestamp: string;
};
