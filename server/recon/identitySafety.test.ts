import { describe, expect, it } from "vitest";
import { identitySafetyForTests, IDENTITY_SOURCE_POLICY } from "./identitySafety";

describe("ReconGPT identity-safety controls", () => {
  it("requires explicit confirmation for protected identity paths", () => {
    expect(identitySafetyForTests.consentGranted(undefined, "email-ownership-confirmed")).toBe(false);
    expect(identitySafetyForTests.consentGranted({ emailOwnershipConfirmed: true }, "email-ownership-confirmed")).toBe(true);
    expect(identitySafetyForTests.consentGranted({ targetAuthorization: true }, "community-admin-confirmed")).toBe(false);
    expect(identitySafetyForTests.consentGranted(undefined, "public-source")).toBe(true);
  });

  it("redacts direct contact and location values", () => {
    expect(identitySafetyForTests.redactEmail("analyst@example.com")).toBe("a•••@example.com");
    expect(identitySafetyForTests.redactCoordinates(51.5074, -0.1278)).toEqual({ coarseLatitude: 51.5, coarseLongitude: -0.1, exactCoordinatesRedacted: true });
  });

  it("keeps community collection disabled and onion research lead-only", () => {
    expect(IDENTITY_SOURCE_POLICY.communities.enabled).toBe(false);
    expect(IDENTITY_SOURCE_POLICY.onionIndex.limitations.join(" ")).toMatch(/never opens/i);
  });
});
