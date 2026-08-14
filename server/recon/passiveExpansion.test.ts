import { describe, expect, it } from "vitest";
import { passiveExpansionSafetyForTests } from "./passiveExpansion";

describe("ReconGPT passive-expansion domain safety", () => {
  it("derives a public-suffix-aware registrable domain for mail, timeline, advisory, and brand collectors", () => {
    expect(passiveExpansionSafetyForTests.rootDomain("api.eu.example.co.uk")).toBe("example.co.uk");
    expect(passiveExpansionSafetyForTests.rootDomain("app.example.com.au")).toBe("example.com.au");
    expect(passiveExpansionSafetyForTests.rootDomain("registry.example.gov.uk")).toBe("example.gov.uk");
  });

  it("keeps local and private destinations ineligible for public-source collection", () => {
    expect(passiveExpansionSafetyForTests.blockedHost("localhost")).toBe(true);
    expect(passiveExpansionSafetyForTests.blockedHost("collector.internal")).toBe(true);
    expect(passiveExpansionSafetyForTests.privateIpv4("172.16.4.9")).toBe(true);
    expect(passiveExpansionSafetyForTests.privateIpv6("fc00::7")).toBe(true);
  });
});
