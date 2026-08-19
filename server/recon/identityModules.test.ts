import { describe, expect, it } from "vitest";
import { communityIntegrationStatus, consentBoundEmailPosture, onionIndexLeads, publicSocialProfileLinks } from "./identityModules";
import { parseTarget } from "./target";

const options = { dorkIntensity: "balanced" as const };

describe("ReconGPT identity-module collection boundaries", () => {
  it("does not make email identity requests without an ownership declaration", async () => {
    const result = await consentBoundEmailPosture(parseTarget("analyst@example.com"), options);
    expect(result.findings).toEqual([]);
    expect(result.notices?.[0]).toMatch(/Confirm ownership/i);
  });

  it("returns review-only public social and onion links without opening onion content", async () => {
    const social = await publicSocialProfileLinks(parseTarget("octocat"));
    const onion = await onionIndexLeads(parseTarget("example.com"));
    expect(social.findings[0].data.profiles).toHaveLength(3);
    expect(onion.findings[0].data.automatedFetch).toBe(false);
    expect(onion.findings[0].leadStatus).toBe("review");
  });

  it("leaves community integrations disabled without explicit administrator controls", async () => {
    const result = await communityIntegrationStatus(parseTarget("example.com"), options);
    expect(result.findings[0].data.connectorEnabled).toBe(false);
  });
});
