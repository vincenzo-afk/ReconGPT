import { describe, expect, it } from "vitest";
import { modulesFor } from "./modules";
import { parseTarget } from "./target";

const options = { dorkIntensity: "balanced" as const };

describe("ReconGPT passive module routing", () => {
  it("selects passive web, archive, exposure, and provider modules for a domain", () => {
    const ids = modulesFor(parseTarget("example.com"), options).map(module => module.id);
    expect(ids).toEqual(expect.arrayContaining(["crt-subdomains", "dns-posture", "dns-crosscheck", "wayback", "common-crawl", "public-web-surface", "exposure-research", "routed-prefix", "shodan", "virustotal"]));
  });

  it("adds document metadata for URL targets without treating it as a domain-only module", () => {
    const ids = modulesFor(parseTarget("https://example.com/report.pdf"), options).map(module => module.id);
    expect(ids).toContain("document-metadata");
  });

  it("routes phone and ASN targets to their non-enriching public research modules", () => {
    expect(modulesFor(parseTarget("+1 212 555 0100"), options).map(module => module.id)).toEqual(["phone-research"]);
    expect(modulesFor(parseTarget("AS15169"), options).map(module => module.id)).toEqual(["asn-research"]);
  });
});
