import { describe, expect, it } from "vitest";
import { appRouter } from "../routers";
import { communityIntegrationStatus } from "./identityModules";
import { defaultCommunityControls, identitySafetyForTests } from "./identitySafety";
import type { ReconTarget } from "./types";

const target: ReconTarget = { raw: "example.com", normalized: "example.com", type: "domain", hostname: "example.com", domain: "example.com" };

describe("community controls", () => {
  it("normalizes selected scopes, bounds their count, and preserves a compact audit trail", () => {
    const scopes = identitySafetyForTests.normalizeCommunityScopes([
      { provider: "discord", scopeId: "guild-1", label: "Authorized research guild" },
      { provider: "discord", scopeId: "guild-1", label: "Duplicate" },
      { provider: "telegram", scopeId: "channel-1", label: "Approved channel" },
      { provider: "unsupported", scopeId: "x", label: "Ignored" },
    ]);
    expect(scopes).toEqual([
      { provider: "discord", scopeId: "guild-1", label: "Authorized research guild" },
      { provider: "telegram", scopeId: "channel-1", label: "Approved channel" },
    ]);
    const audited = identitySafetyForTests.recordCommunityAudit({ ...defaultCommunityControls(), scopes }, 9, "configured");
    expect(audited.audit).toHaveLength(1);
    expect(audited.audit[0]).toMatchObject({ actorUserId: 9, action: "configured", scopeCount: 2 });
  });

  it("reports configured scopes but requires consent and respects the pause lifecycle", async () => {
    const controls = { ...defaultCommunityControls(), connectorEnabled: true, scopes: [{ provider: "discord" as const, scopeId: "guild-1", label: "Authorized research guild" }] };
    const withoutConsent = await communityIntegrationStatus(target, { dorkIntensity: "focused", communityControls: controls });
    expect(withoutConsent.findings[0].data.connectorEnabled).toBe(false);

    const paused = await communityIntegrationStatus(target, { dorkIntensity: "focused", consent: { communityAdminConfirmed: true }, communityControls: { ...controls, paused: true } });
    expect(paused.findings[0].data.connectorEnabled).toBe(false);
    expect(paused.findings[0].limitations?.join(" ")).toContain("paused");

    const ready = await communityIntegrationStatus(target, { dorkIntensity: "focused", consent: { communityAdminConfirmed: true }, communityControls: controls });
    expect(ready.findings[0].data.connectorEnabled).toBe(true);
    expect(ready.findings[0].data).toMatchObject({ configured: { selectedScopeCount: 1, retentionDays: 7 } });
  });

  it("rejects community configuration from non-administrator accounts before any database action", async () => {
    const caller = appRouter.createCaller({ user: { id: 42, role: "user" } as any, req: {} as any, res: {} as any });
    await expect(caller.settings.saveCommunity({ connectorEnabled: true, paused: false, retentionDays: 7, scopes: [{ provider: "telegram", scopeId: "approved-channel", label: "Approved channel" }] })).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(caller.settings.purgeCommunity()).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});
