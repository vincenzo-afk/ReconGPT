import { createHash, randomUUID } from "node:crypto";
import { IDENTITY_SOURCE_POLICY, consentGranted, defaultCommunityControls, identityMetadata, redactEmail } from "./identitySafety";
import type { ModuleResult, ReconFinding, ReconOptions, ReconTarget } from "./types";

const uid = () => randomUUID().slice(0, 16);
const fetchBounded = async (url: string, accept: string) => {
  try {
    const response = await fetch(url, { redirect: "manual", headers: { "User-Agent": "ReconGPT/2.2 (consent-gated-public-evidence)", Accept: accept }, signal: AbortSignal.timeout(7_000) });
    const body = response.ok ? (await response.text()).slice(0, 32_000) : "";
    return { status: response.status, ok: response.ok, body };
  } catch { return { status: null, ok: false, body: "" }; }
};

export async function consentBoundEmailPosture(target: ReconTarget, options: ReconOptions): Promise<ModuleResult> {
  const email = target.normalized;
  if (!consentGranted(options.consent, "email-ownership-confirmed")) {
    return { findings: [], notices: ["Email account discovery is not run. Confirm ownership or authorization in the collection controls before using public identity endpoints."] };
  }
  const [webfinger, pgp] = await Promise.all([
    fetchBounded(`https://${target.domain}/.well-known/webfinger?resource=${encodeURIComponent(`acct:${email}`)}`, "application/jrd+json, application/json"),
    fetchBounded(`https://keys.openpgp.org/vks/v1/by-email/${encodeURIComponent(email)}`, "application/pgp-keys, application/octet-stream"),
  ]);
  const signals = [
    { provider: "WebFinger", status: webfinger.status, publicIdentityEndpointSignal: webfinger.ok, source: `https://${target.domain}/.well-known/webfinger` },
    { provider: "OpenPGP key directory", status: pgp.status, publicIdentityEndpointSignal: pgp.ok, source: "https://keys.openpgp.org" },
  ];
  const positive = signals.filter(signal => signal.publicIdentityEndpointSignal);
  const finding: ReconFinding = {
    id: uid(), moduleId: "email-ownership-posture", category: "Identity", title: "Consent-bound public email posture", summary: `Checked ${signals.length} public identity endpoints for an authorized email address; ${positive.length} public endpoint signal(s) were returned. This does not enumerate accounts, prove registration, or prove identity.`, severity: "low", confidence: positive.length ? 82 : 65,
    evidenceQuality: "context", leadStatus: "review", collectedAt: new Date().toISOString(), sourceCount: signals.length, ...identityMetadata("contact", "email-ownership-confirmed", "redacted"),
    limitations: [...IDENTITY_SOURCE_POLICY.emailPosture.limitations, "A missing response is not evidence that an email is absent from a service."], data: { email: redactEmail(email), signals, policy: IDENTITY_SOURCE_POLICY.emailPosture },
  };
  return { findings: [finding] };
}

export async function publicSocialProfileLinks(target: ReconTarget): Promise<ModuleResult> {
  const username = target.normalized.replace(/^@/, "");
  const profiles = [
    { platform: "Instagram", url: `https://www.instagram.com/${encodeURIComponent(username)}/` },
    { platform: "Mastodon", url: `https://mastodon.social/@${encodeURIComponent(username)}` },
    { platform: "Bluesky", url: `https://bsky.app/profile/${encodeURIComponent(username)}.bsky.social` },
  ];
  const finding: ReconFinding = {
    id: uid(), moduleId: "public-social-profile-links", category: "Social Intelligence", title: "Public social-profile review links", summary: `Prepared ${profiles.length} public-profile review links for the supplied handle. ReconGPT does not log in, bypass platform controls, infer hidden contact fields, or attribute a profile to a person.`, severity: "low", confidence: 58,
    evidenceQuality: "lead", leadStatus: "review", collectedAt: new Date().toISOString(), sourceCount: profiles.length, ...identityMetadata("public", "public-source"), limitations: [...IDENTITY_SOURCE_POLICY.socialProfile.limitations],
    data: { username, profiles, policy: IDENTITY_SOURCE_POLICY.socialProfile }, entities: profiles.map(profile => ({ type: "social_profile" as const, value: profile.url, label: profile.platform, confidence: 55, metadata: { username, collectionMode: "manual-public-review" } })),
  };
  return { findings: [finding] };
}

export async function onionIndexLeads(target: ReconTarget): Promise<ModuleResult> {
  const query = target.domain || target.normalized;
  const searchUrl = `https://ahmia.fi/search/?q=${encodeURIComponent(query)}`;
  const finding: ReconFinding = {
    id: uid(), moduleId: "onion-index-leads", category: "Threat Intelligence", title: "Onion-index research lead", summary: "Prepared a public onion-index query lead for authorized analyst review. No onion URL was opened, crawled, downloaded, or stored.", severity: "low", confidence: 45, sourceUrl: searchUrl,
    evidenceQuality: "lead", leadStatus: "review", collectedAt: new Date().toISOString(), sourceCount: 1, ...identityMetadata("public", "public-source", "ephemeral"), limitations: [...IDENTITY_SOURCE_POLICY.onionIndex.limitations],
    data: { query, publicIndexUrl: searchUrl, automatedFetch: false, policy: IDENTITY_SOURCE_POLICY.onionIndex },
  };
  return { findings: [finding] };
}

export async function communityIntegrationStatus(target: ReconTarget, options: ReconOptions): Promise<ModuleResult> {
  const controls = options.communityControls || defaultCommunityControls();
  const permitted = controls.connectorEnabled && !controls.paused && controls.scopes.length > 0 && consentGranted(options.consent, "community-admin-confirmed");
  const finding: ReconFinding = {
    id: uid(), moduleId: "community-integration-status", category: "Community Intelligence", title: "Discord and Telegram integration status", summary: "Community collection is disabled by default. ReconGPT does not discover communities, enumerate users, collect messages, or connect a bot without an administrator-configured, explicitly selected scope.", severity: "low", confidence: 100,
    evidenceQuality: "context", leadStatus: "verified", collectedAt: new Date().toISOString(), sourceCount: 0, ...identityMetadata("community", "community-admin-confirmed", "ephemeral"), limitations: [...IDENTITY_SOURCE_POLICY.communities.limitations, permitted ? "This scaffold is authorized only for the configured selected scopes; collection remains disabled until a provider connector is separately implemented." : controls.paused ? "Community integration is paused by an administrator." : controls.scopes.length === 0 ? "No selected community scope is configured." : "No community connector has been enabled for this run."],
    data: { target: target.normalized, connectorEnabled: permitted, configured: { connectorEnabled: controls.connectorEnabled, paused: controls.paused, retentionDays: controls.retentionDays, selectedScopeCount: controls.scopes.length, selectedScopes: controls.scopes.map(scope => ({ provider: scope.provider, label: scope.label })), lastPurgeAt: controls.lastPurgeAt }, requiredControls: ["workspace-owner installation", "administrator confirmation", "selected-scope allowlist", "pause", "purge", "audit trail", "retention limit"], policy: IDENTITY_SOURCE_POLICY.communities },
  };
  return { findings: [finding] };
}

export function mediaFingerprint(bytes: Buffer) { return createHash("sha256").update(bytes).digest("hex").slice(0, 16); }
export const identityModulesForTests = { mediaFingerprint };
