import { describe, expect, it } from "vitest";
import { modulesFor } from "./modules";
import { parseTarget, reconRequestSchema } from "./target";

describe("ReconGPT target parsing", () => {
  it("normalizes domains and URLs while preserving reconnaissance type", () => {
    expect(parseTarget("HTTPS://WWW.Example.COM/login")).toMatchObject({ type: "url", hostname: "www.example.com", domain: "example.com" });
    expect(parseTarget("Example.COM")).toMatchObject({ type: "domain", normalized: "example.com" });
  });

  it("identifies identity and network targets", () => {
    expect(parseTarget("Analyst@Example.com")).toMatchObject({ type: "email", normalized: "analyst@example.com", domain: "example.com" });
    expect(parseTarget("1.1.1.1")).toMatchObject({ type: "ip" });
    expect(parseTarget("AS13335")).toMatchObject({ type: "asn", normalized: "AS13335" });
    expect(parseTarget("openai")).toMatchObject({ type: "username", normalized: "openai" });
  });

  it("limits deep-mode module execution to applicable, enabled passive modules", () => {
    const target = parseTarget("example.com");
    const modules = modulesFor(target, { dorkIntensity: "deep", enabledModules: ["dns-posture", "wayback"] });
    expect(modules.map(module => module.id)).toEqual(["dns-posture", "wayback"]);
    expect(modules.every(module => module.appliesTo.includes("domain"))).toBe(true);
  });

  it("rejects unsafe oversized command inputs", () => {
    const result = reconRequestSchema.safeParse({ target: "x".repeat(513) });
    expect(result.success).toBe(false);
  });
});
