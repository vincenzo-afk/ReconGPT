import { describe, expect, it } from "vitest";
import { ENV } from "../_core/env";

const required = (name: string) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not configured for provider validation.`);
  return value;
};

async function expectSuccessfulProviderResponse(name: string, url: string, init?: RequestInit) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(8_000) });
  expect(response.status, `${name} credential validation returned HTTP ${response.status}`).toBeGreaterThanOrEqual(200);
  expect(response.status, `${name} credential validation returned HTTP ${response.status}`).toBeLessThan(300);
}

describe("server-only provider credentials", () => {
  it("authenticates the configured passive intelligence providers", async () => {
    expect(ENV.ipinfoToken).toBe(required("IPINFO_API_KEY"));
    await Promise.all([
      expectSuccessfulProviderResponse("Shodan", `https://api.shodan.io/api-info?key=${encodeURIComponent(required("SHODAN_API_KEY"))}`),
      expectSuccessfulProviderResponse("VirusTotal", "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", { headers: { "x-apikey": required("VIRUSTOTAL_API_KEY") } }),
      expectSuccessfulProviderResponse("AbuseIPDB", "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90", { headers: { Key: required("ABUSEIPDB_API_KEY"), Accept: "application/json" } }),
      expectSuccessfulProviderResponse("urlscan.io", "https://urlscan.io/api/v1/search/?q=domain%3Aexample.com", { headers: { "API-Key": required("URLSCAN_API_KEY") } }),
      expectSuccessfulProviderResponse("IPinfo", `https://ipinfo.io/json?token=${encodeURIComponent(required("IPINFO_API_KEY"))}`),
    ]);
  }, 15_000);
});
