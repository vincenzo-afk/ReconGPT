import { describe, expect, it } from "vitest";
import { crawlerSafetyForTests, modulesFor } from "./modules";
import { parseTarget } from "./target";

const options = { dorkIntensity: "balanced" as const };

describe("ReconGPT passive module routing", () => {
  it("selects passive web, archive, exposure, and provider modules for a domain", () => {
    const ids = modulesFor(parseTarget("example.com"), options).map(module => module.id);
    expect(ids).toEqual(expect.arrayContaining(["crt-subdomains", "dns-posture", "dns-crosscheck", "wayback", "common-crawl", "public-search", "public-web-crawl", "public-web-surface", "exposure-research", "routed-prefix", "shodan", "virustotal"]));
  });

  it("adds document metadata for URL targets without treating it as a domain-only module", () => {
    const ids = modulesFor(parseTarget("https://example.com/report.pdf"), options).map(module => module.id);
    expect(ids).toContain("document-metadata");
  });

  it("routes phone and ASN targets to their non-enriching public research modules", () => {
    expect(modulesFor(parseTarget("+1 212 555 0100"), options).map(module => module.id)).toEqual(["phone-research"]);
    expect(modulesFor(parseTarget("AS15169"), options).map(module => module.id)).toEqual(["asn-research"]);
  });

  it("rejects non-public URL schemes and private-network crawl destinations before collection", () => {
    expect(crawlerSafetyForTests.normalizedHttpUrl("file:///etc/passwd")).toBeNull();
    expect(crawlerSafetyForTests.normalizedHttpUrl("https://example.com/path#fragment")?.toString()).toBe("https://example.com/path");
    expect(crawlerSafetyForTests.privateIpv4("127.0.0.1")).toBe(true);
    expect(crawlerSafetyForTests.privateIpv4("10.1.2.3")).toBe(true);
    expect(crawlerSafetyForTests.privateIpv4("8.8.8.8")).toBe(false);
    expect(crawlerSafetyForTests.privateIpv6("::1")).toBe(true);
    expect(crawlerSafetyForTests.blockedHost("localhost")).toBe(true);
    expect(crawlerSafetyForTests.blockedHost("metadata.internal")).toBe(true);
  });
});
