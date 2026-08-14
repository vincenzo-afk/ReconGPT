import { z } from "zod";
import type { ReconTarget, TargetType } from "./types";

const domainPattern = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)\.(?:[a-z]{2,63})(?:\.[a-z]{2,63})?$/i;
const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phonePattern = /^\+?[1-9]\d{6,14}$/;
const asnPattern = /^AS\d{1,10}$/i;

export const reconRequestSchema = z.object({
  target: z.string().trim().min(2).max(512),
  context: z.string().trim().max(2000).optional().default(""),
  dorkIntensity: z.enum(["focused", "balanced", "deep"]).default("balanced"),
  enabledModules: z.array(z.string()).max(64).optional(),
});

function normalizeHostname(value: string) {
  return value.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
}

export function parseTarget(rawInput: string): ReconTarget {
  const raw = rawInput.trim();
  const normalizedCandidate = normalizeHostname(raw);
  if (ipv4Pattern.test(normalizedCandidate) || normalizedCandidate.includes(":")) {
    return { raw, normalized: normalizedCandidate, type: "ip", hostname: normalizedCandidate };
  }
  if (emailPattern.test(raw)) {
    const normalized = raw.toLowerCase();
    return { raw, normalized, type: "email", domain: normalized.split("@")[1] };
  }
  if (asnPattern.test(raw)) return { raw, normalized: raw.toUpperCase(), type: "asn" };
  if (phonePattern.test(raw.replace(/[\s().-]/g, ""))) return { raw, normalized: raw.replace(/[\s().-]/g, ""), type: "phone" };
  try {
    if (/^https?:\/\//i.test(raw)) {
      const url = new URL(raw);
      return { raw, normalized: url.toString(), type: "url", hostname: url.hostname, domain: normalizeHostname(url.hostname) };
    }
  } catch { /* fall through */ }
  if (domainPattern.test(normalizedCandidate)) {
    return { raw, normalized: normalizedCandidate, type: "domain", hostname: normalizedCandidate, domain: normalizedCandidate };
  }
  if (raw.includes(" ")) return { raw, normalized: raw, type: "company" };
  return { raw, normalized: raw.replace(/^@/, "").toLowerCase(), type: "username" };
}

export function moduleApplies(moduleTypes: TargetType[], target: ReconTarget) {
  return moduleTypes.includes(target.type);
}
