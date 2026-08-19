import type { CommunityControls, CommunityProvider, CommunityScope, ConsentBasis, DataSensitivity, IdentityConsent, RetentionClass } from "./types";

export const IDENTITY_SOURCE_POLICY = {
  usernamePresence: { enabled: true, mode: "public-url-pattern", limitations: ["A reachable public profile URL is not proof of identity, ownership, or activity."] },
  emailPosture: { enabled: true, mode: "ownership-gated-public-evidence", limitations: ["No sign-up, login, recovery, verification, invite, or password-reset flow is requested."] },
  mediaMetadata: { enabled: true, mode: "analyst-provided-file", limitations: ["Only provided images may be parsed; coordinates are redacted by default."] },
  socialProfile: { enabled: true, mode: "public-or-authorized", limitations: ["Private content, hidden contact data, and identity inference are excluded."] },
  onionIndex: { enabled: true, mode: "public-index-lead-only", limitations: ["ReconGPT never opens, crawls, downloads, or stores onion content."] },
  communities: { enabled: false, mode: "administrator-configured-selected-scope-only", limitations: ["Disabled until an administrator configures explicitly selected community scopes. No account discovery, user enumeration, or direct-message collection is supported."] },
} as const;

export function consentGranted(consent: IdentityConsent | undefined, basis: ConsentBasis) {
  return basis === "public-source" || (basis === "target-authorization" && consent?.targetAuthorization === true) || (basis === "email-ownership-confirmed" && consent?.emailOwnershipConfirmed === true) || (basis === "media-authorization-confirmed" && consent?.mediaAuthorizationConfirmed === true) || (basis === "community-admin-confirmed" && consent?.communityAdminConfirmed === true);
}
export function redactEmail(value: string) { const [local, domain] = value.split("@"); return local && domain ? `${local.slice(0, 1)}•••@${domain}` : "[redacted email]"; }
export function redactCoordinates(latitude: number, longitude: number) { return { coarseLatitude: Math.round(latitude * 10) / 10, coarseLongitude: Math.round(longitude * 10) / 10, exactCoordinatesRedacted: true }; }
export function identityMetadata(sensitivity: DataSensitivity, basis: ConsentBasis, retentionClass: RetentionClass = sensitivity === "location" ? "redacted" : "standard") { return { dataSensitivity: sensitivity, consentBasis: basis, retentionClass } as const; }
export function defaultCommunityControls(): CommunityControls { return { connectorEnabled: false, paused: false, retentionDays: 7, scopes: [], audit: [] }; }
export function normalizeCommunityScopes(value: unknown): CommunityScope[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  return value.flatMap((raw): CommunityScope[] => {
    if (!raw || typeof raw !== "object") return [];
    const item = raw as Record<string, unknown>;
    const provider = item.provider === "discord" || item.provider === "telegram" ? item.provider as CommunityProvider : null;
    const scopeId = typeof item.scopeId === "string" ? item.scopeId.trim() : "";
    const label = typeof item.label === "string" ? item.label.trim() : "";
    const key = `${provider}:${scopeId}`;
    if (!provider || !scopeId || !label || scopeId.length > 128 || label.length > 128 || seen.has(key)) return [];
    seen.add(key); return [{ provider, scopeId, label }];
  }).slice(0, 10);
}
export function parseCommunityControls(value: string | null | undefined): CommunityControls {
  try {
    const raw = value ? JSON.parse(value) as Record<string, unknown> : {};
    const audit = Array.isArray(raw.audit) ? raw.audit.filter(entry => entry && typeof entry === "object").slice(-40) as CommunityControls["audit"] : [];
    return { connectorEnabled: raw.connectorEnabled === true, paused: raw.paused === true, retentionDays: typeof raw.retentionDays === "number" && Number.isInteger(raw.retentionDays) && raw.retentionDays >= 1 && raw.retentionDays <= 30 ? raw.retentionDays : 7, scopes: normalizeCommunityScopes(raw.scopes), audit, lastPurgeAt: typeof raw.lastPurgeAt === "string" ? raw.lastPurgeAt : undefined };
  } catch { return defaultCommunityControls(); }
}
export function recordCommunityAudit(controls: CommunityControls, actorUserId: number, action: CommunityControls["audit"][number]["action"]): CommunityControls {
  return { ...controls, audit: [...controls.audit, { at: new Date().toISOString(), actorUserId, action, scopeCount: controls.scopes.length }].slice(-40) };
}
export const identitySafetyForTests = { consentGranted, redactEmail, redactCoordinates, identityMetadata, defaultCommunityControls, normalizeCommunityScopes, parseCommunityControls, recordCommunityAudit };
