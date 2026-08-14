import { resolve4, resolve6, resolveCaa, resolveTxt } from "node:dns/promises";
import { getDomain } from "tldts";
import type { ModuleResult, ReconFinding, ReconOptions, ReconTarget, RiskLevel } from "./types";

const REQUEST_TIMEOUT_MS = 10_000;
const PUBLIC_AGENT = "ReconGPT/2.2 (authorized-passive-research)";
const privateIpv4 = (value: string) => /^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[0-1])\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.1[89]\.|198\.51\.100\.|203\.0\.113\.|224\.|23\d\.|24\d\.|25[0-5]\.)/.test(value);
const privateIpv6 = (value: string) => /^(?:::1|fe[89ab]|f[cd]|::ffff:(?:0*:)?(?:127|10|192\.168)\.)/i.test(value);
const blockedHost = (hostname: string) => hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal") || hostname.endsWith(".test") || hostname.endsWith(".invalid");
const isIp = (value: string) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":");
const rootDomain = (hostname: string) => getDomain(hostname, { allowPrivateDomains: false }) || hostname.toLowerCase();
const hostOf = (target: ReconTarget) => target.hostname || target.domain || target.normalized;
const uid = () => crypto.randomUUID().slice(0, 16);
const googleSearch = (query: string) => `https://www.google.com/search?q=${encodeURIComponent(query)}`;

function evidenceFinding(moduleId: string, category: string, title: string, summary: string, data: Record<string, unknown>, severity: RiskLevel = "low", confidence = 82, sourceUrl?: string, quality: ReconFinding["evidenceQuality"] = "direct", leadStatus: ReconFinding["leadStatus"] = "verified", limitations: string[] = []): ReconFinding {
  return { id: uid(), moduleId, category, title, summary, severity, confidence, sourceUrl, data, evidenceQuality: quality, leadStatus, collectedAt: new Date().toISOString(), sourceCount: sourceUrl ? 1 : 0, limitations };
}

async function safe<T>(fallback: T, action: () => Promise<T>) { try { return await action(); } catch { return fallback; } }
async function publicHost(hostname: string) {
  if (blockedHost(hostname) || privateIpv4(hostname) || privateIpv6(hostname)) return false;
  if (isIp(hostname)) return true;
  const [ipv4, ipv6] = await Promise.all([safe<string[]>([], () => resolve4(hostname)), safe<string[]>([], () => resolve6(hostname))]);
  const addresses = [...ipv4, ...ipv6];
  return addresses.length > 0 && addresses.every(address => !privateIpv4(address) && !privateIpv6(address));
}

async function safePublicText(url: string) {
  const parsed = new URL(url);
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || !(await publicHost(parsed.hostname))) return null;
  const response = await fetch(parsed, { redirect: "manual", headers: { "User-Agent": PUBLIC_AGENT, Accept: "text/plain,text/*;q=0.8" }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  const type = response.headers.get("content-type") || "";
  if (!response.ok || !/text\/(plain|html)|application\/security-txt/i.test(type)) return null;
  return (await response.text()).slice(0, 12_000);
}

async function publicJson<T>(url: string, init: RequestInit = {}) {
  const response = await fetch(url, { ...init, headers: { "User-Agent": PUBLIC_AGENT, ...(init.headers || {}) }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`public source returned ${response.status}`);
  return response.json() as Promise<T>;
}

function toText(records: string[][]) { return records.map(record => record.join("")).filter(Boolean); }

export async function emailDisclosureIntelligence(target: ReconTarget): Promise<ModuleResult> {
  const host = target.type === "email" ? target.domain || target.normalized.split("@")[1] : hostOf(target);
  const domain = rootDomain(host);
  const [caa, mtaStsDns, tlsRpt, bimi, dnskey] = await Promise.all([
    safe<Awaited<ReturnType<typeof resolveCaa>>>([], () => resolveCaa(domain)),
    safe<string[][]>([], () => resolveTxt(`_mta-sts.${domain}`)),
    safe<string[][]>([], () => resolveTxt(`_smtp._tls.${domain}`)),
    safe<string[][]>([], () => resolveTxt(`default._bimi.${domain}`)),
    safe<{ Status?: number; AD?: boolean; Answer?: unknown[] } | null>(null, () => publicJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DNSKEY&do=1`)),
  ]);
  const policyText = await safePublicText(`https://mta-sts.${domain}/.well-known/mta-sts.txt`);
  const securityWellKnown = await safePublicText(`https://${host}/.well-known/security.txt`);
  const securityRoot = securityWellKnown ? null : await safePublicText(`https://${host}/security.txt`);
  const securityText = securityWellKnown || securityRoot;
  const securityUrl = securityWellKnown ? `https://${host}/.well-known/security.txt` : securityRoot ? `https://${host}/security.txt` : null;
  const contacts = securityText ? securityText.split(/\r?\n/).filter(line => /^Contact:/i.test(line)).map(line => line.replace(/^Contact:\s*/i, "").trim()).slice(0, 12) : [];
  const data = {
    domain, host, certificateAuthorityAuthorization: caa, mtaSts: { dns: toText(mtaStsDns), policyAvailable: Boolean(policyText), policy: policyText }, tlsReporting: toText(tlsRpt), bimi: toText(bimi), dnssec: { dnskeyAnswers: dnskey?.Answer?.length || 0, authenticatedData: dnskey?.AD === true, status: dnskey?.Status ?? null }, securityTxt: { available: Boolean(securityText), url: securityUrl, contacts, content: securityText }, collectionPolicy: "Public DNS and bounded public HTTPS GETs only; no SMTP, mailbox, relay, or account interaction.", limitation: "DNSSEC, MTA-STS, BIMI, and security.txt absence are not conclusive evidence of misconfiguration; records can be delegated, scoped, or intentionally unavailable.",
  };
  const record = evidenceFinding("email-disclosure", "Domain", "Email security and disclosure posture", `Collected public CAA, MTA-STS, TLS-RPT, BIMI, DNSSEC, and security-contact signals for ${domain}.`, data, "low", 92, securityUrl || `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=CAA`, "direct", "verified", [String(data.limitation)]);
  record.sourceCount = [caa.length > 0, mtaStsDns.length > 0, tlsRpt.length > 0, bimi.length > 0, Boolean(securityText), Boolean(dnskey)].filter(Boolean).length;
  record.entities = [{ type: "domain", value: domain, confidence: 97 }, ...(securityUrl ? [{ type: "url" as const, value: securityUrl, confidence: 96 }] : [])];
  return { findings: [record], notices: securityText ? undefined : ["No public security.txt was collected from the standard well-known or root path; this is not proof that no disclosure channel exists."] };
}

export async function certificateTimeline(target: ReconTarget): Promise<ModuleResult> {
  const domain = rootDomain(hostOf(target));
  const rows = await publicJson<Array<{ name_value?: string; issuer_name?: string; not_before?: string; not_after?: string; serial_number?: string; id?: number }>>(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`);
  const certificates = rows.slice(0, 500).map(row => ({ names: String(row.name_value || "").split("\n").map(value => value.trim().replace(/^\*\./, "").toLowerCase()).filter(Boolean), issuer: row.issuer_name || "unknown issuer", notBefore: row.not_before || null, notAfter: row.not_after || null, serial: row.serial_number || null, id: row.id || null })).filter(item => item.names.some(name => name === domain || name.endsWith(`.${domain}`)));
  const issuers = Array.from(new Set(certificates.map(item => item.issuer))).slice(0, 20);
  const names = Array.from(new Set(certificates.flatMap(item => item.names))).slice(0, 150);
  const dated = certificates.filter(item => item.notBefore).sort((left, right) => String(left.notBefore).localeCompare(String(right.notBefore)));
  const timeline = dated.slice(0, 12).concat(dated.length > 24 ? dated.slice(-12) : dated.slice(12)).map(item => ({ notBefore: item.notBefore, notAfter: item.notAfter, issuer: item.issuer, names: item.names.slice(0, 12) }));
  const data = { domain, certificateCount: certificates.length, observedNames: names, issuers, firstObserved: dated[0]?.notBefore || null, mostRecentObserved: dated.at(-1)?.notBefore || null, timeline, limitation: "Certificate Transparency describes publicly logged certificate activity and related names. It does not prove current DNS control, hosting, or organizational ownership." };
  const record = evidenceFinding("certificate-timeline", "Historical", "Certificate transparency change timeline", `Normalized ${certificates.length} publicly logged certificate record(s) and ${names.length} related certificate name(s) for ${domain}.`, data, "low", 93, `https://crt.sh/?q=%25.${domain}`, "corroborated", "verified", [String(data.limitation)]);
  record.sourceCount = Math.min(2, certificates.length ? 1 : 0) + (issuers.length > 1 ? 1 : 0);
  record.entities = [{ type: "domain", value: domain, confidence: 97 }, ...names.slice(0, 80).map(value => ({ type: value === domain ? "domain" as const : "subdomain" as const, value, confidence: 89 }))];
  return { findings: [record], notices: certificates.length ? undefined : ["No matching Certificate Transparency rows were returned; this does not prove the domain has never used certificates."] };
}

export async function historicalWebChange(target: ReconTarget): Promise<ModuleResult> {
  const domain = rootDomain(hostOf(target));
  const rows = await publicJson<Array<[string, string, string, string]>>(`https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=timestamp,original,statuscode,digest&filter=statuscode:200&collapse=digest&limit=80`);
  const entries = rows.slice(1).map(row => ({ timestamp: row[0], url: row[1], status: row[2], digest: row[3] })).filter(entry => entry.timestamp && entry.url);
  const digestChanges = new Set(entries.map(entry => entry.digest).filter(Boolean)).size;
  const monthly = Object.entries(entries.reduce<Record<string, number>>((summary, entry) => { const month = entry.timestamp.slice(0, 6); summary[month] = (summary[month] || 0) + 1; return summary; }, {})).slice(0, 36).map(([month, count]) => ({ month, count }));
  const data = { domain, snapshots: entries.slice(0, 80), firstSnapshot: entries[0] || null, latestSnapshot: entries.at(-1) || null, distinctArchivedContentDigests: digestChanges, monthlySnapshotCounts: monthly, limitation: "Archive index digest changes indicate historically distinct captures, not a verified security, ownership, or content change. ReconGPT does not retrieve archived bodies through this module." };
  const record = evidenceFinding("historical-web-change", "Historical", "Public web-change timeline", `Archive indexes returned ${entries.length} successful historical capture record(s) with ${digestChanges} distinct indexed content digest(s).`, data, "low", 89, `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json`, "corroborated", "verified", [String(data.limitation)]);
  record.sourceCount = entries.length ? 1 : 0;
  record.entities = [{ type: "domain", value: domain, confidence: 95 }, ...entries.slice(0, 40).map(entry => ({ type: "url" as const, value: entry.url, confidence: 83 }))];
  return { findings: [record], notices: entries.length ? undefined : ["No successful archive index records were returned; archive availability is incomplete and not evidence of absence."] };
}

export async function githubSupplyChain(target: ReconTarget): Promise<ModuleResult> {
  const username = target.normalized.replace(/^@/, "");
  const repos = await publicJson<Array<Record<string, unknown>>>(`https://api.github.com/users/${encodeURIComponent(username)}/repos?per_page=100&sort=updated`, { headers: { Accept: "application/vnd.github+json" } });
  const normalized = repos.filter(repo => !repo.message).slice(0, 80).map(repo => ({ name: repo.name, url: repo.html_url, description: repo.description, language: repo.language, license: (repo.license as Record<string, unknown> | null)?.spdx_id || null, archived: repo.archived, disabled: repo.disabled, fork: repo.fork, defaultBranch: repo.default_branch, pushedAt: repo.pushed_at, updatedAt: repo.updated_at, visibility: repo.visibility || "public", topics: Array.isArray(repo.topics) ? repo.topics.slice(0, 15) : [] }));
  const languages = Array.from(new Set(normalized.map(repo => typeof repo.language === "string" ? repo.language : "").filter(Boolean))).slice(0, 20);
  const licenses = Array.from(new Set(normalized.map(repo => typeof repo.license === "string" ? repo.license : "").filter(Boolean))).slice(0, 20);
  const data = { username, publicRepositoryCount: normalized.length, languages, licenses, repositories: normalized, collectionPolicy: "Public GitHub account and repository metadata only; no private repositories, cloning, secret scanning, or credential extraction.", limitation: "A public repository or declared language does not establish organizational ownership, deployment status, dependency use, or vulnerability exposure." };
  const record = evidenceFinding("github-supply-chain", "Supply Chain", "Public software supply-chain profile", `GitHub returned ${normalized.length} visible public repository metadata record(s) for ${username}, spanning ${languages.length} declared language(s).`, data, "low", 95, `https://github.com/${encodeURIComponent(username)}?tab=repositories`, "direct", "verified", [String(data.limitation)]);
  record.sourceCount = normalized.length ? 1 : 0;
  record.entities = [{ type: "username", value: username, confidence: 98 }, ...normalized.slice(0, 35).flatMap(repo => typeof repo.url === "string" ? [{ type: "url" as const, value: repo.url, confidence: 94 }] : [])];
  return { findings: [record], notices: normalized.length ? undefined : ["GitHub returned no visible repository metadata. This may reflect an unavailable source, no public repositories, or account scoping."] };
}

export async function networkOwnershipContext(target: ReconTarget): Promise<ModuleResult> {
  const host = hostOf(target);
  const resolved = target.type === "ip" ? [target.normalized] : await safe<string[]>([], async () => { const [ipv4, ipv6] = await Promise.all([resolve4(host), resolve6(host)]); return [...ipv4, ...ipv6]; });
  const ip = resolved.find(value => !privateIpv4(value) && !privateIpv6(value));
  if (!ip) return { findings: [], notices: ["No public IP address was available for routing ownership enrichment."] };
  const [network, rpki] = await Promise.all([
    safe<Record<string, unknown> | null>(null, () => publicJson(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`)),
    safe<Record<string, unknown> | null>(null, () => publicJson(`https://stat.ripe.net/data/rpki-validation/data.json?resource=${encodeURIComponent(ip)}`)),
  ]);
  const networkData = (network?.data || network || {}) as Record<string, unknown>;
  const rpkiData = (rpki?.data || rpki || {}) as Record<string, unknown>;
  const asns = Array.isArray(networkData.asns) ? networkData.asns.map(value => String(value)) : [];
  const data = { ip, prefix: networkData.prefix || null, holder: networkData.holder || null, asns, rpki: rpkiData, sources: [{ name: "RIPEstat network-info", url: `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}` }, { name: "RIPEstat RPKI validation", url: `https://stat.ripe.net/data/rpki-validation/data.json?resource=${encodeURIComponent(ip)}` }], limitation: "Public routing and RPKI records provide network context. They do not prove present host control, operational responsibility, or malicious activity." };
  const record = evidenceFinding("network-ownership-context", "IP Intelligence", "Network ownership and RPKI context", `Collected public routing ownership and RPKI context for ${ip}${asns.length ? ` across ${asns.length} ASN reference(s)` : ""}.`, data, "low", network ? 88 : 66, `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`, network && rpki ? "corroborated" : "direct", "verified", [String(data.limitation)]);
  record.sourceCount = [network, rpki].filter(Boolean).length;
  record.entities = [{ type: "ip", value: ip, confidence: 98 }, ...asns.slice(0, 12).map(value => ({ type: "asn" as const, value: value.startsWith("AS") ? value : `AS${value}`, confidence: 86 }))];
  record.relationships = asns.slice(0, 12).map(value => ({ sourceValue: ip, targetValue: value.startsWith("AS") ? value : `AS${value}`, relationType: "routed-by", evidence: record.id }));
  return { findings: [record], notices: network || rpki ? undefined : ["Public routing sources did not return usable data for this IP; this module did not infer ownership."] };
}

export async function defensiveBrandLeads(target: ReconTarget, options: ReconOptions): Promise<ModuleResult> {
  const subject = target.type === "company" ? target.normalized.trim().toLowerCase().replace(/[^a-z0-9]/g, "") : rootDomain(hostOf(target)).split(".")[0];
  const tld = target.type === "company" ? "com" : rootDomain(hostOf(target)).split(".").at(-1) || "com";
  const suffixes = ["support", "secure", "login", "verify", "account", "help"];
  const limit = options.dorkIntensity === "focused" ? 3 : options.dorkIntensity === "balanced" ? 5 : suffixes.length;
  const candidates = suffixes.slice(0, limit).map(suffix => `${subject}${suffix}.${tld}`).filter(candidate => candidate.length <= 253).map(candidate => ({ candidate, certificateTransparency: `https://crt.sh/?q=${encodeURIComponent(candidate)}`, rdap: `https://rdap.org/domain/${encodeURIComponent(candidate)}`, publicSearch: googleSearch(`"${candidate}"`) }));
  const data = { subject, candidates, status: "unverified defensive leads", collectionPolicy: "Candidate names are generated locally. ReconGPT does not resolve, visit, register, contact, or attribute candidate domains through this module.", limitation: "Name similarity, public CT records, and search references do not establish impersonation, ownership, intent, or a security incident." };
  const record = evidenceFinding("defensive-brand-leads", "Brand Intelligence", "Defensive brand-monitoring leads", `Generated ${candidates.length} bounded defensive research lead(s) for public analyst validation. No candidate domain was contacted or attributed.`, data, "low", 100, candidates[0]?.certificateTransparency, "lead", "review", [String(data.limitation)]);
  record.sourceCount = 0;
  record.entities = target.type === "company" ? [{ type: "organization", value: target.normalized, confidence: 100 }] : [{ type: "domain", value: rootDomain(hostOf(target)), confidence: 100 }];
  return { findings: [record] };
}

export async function publicAdvisoryPivots(target: ReconTarget): Promise<ModuleResult> {
  const subject = target.type === "company" ? target.normalized : rootDomain(hostOf(target));
  const links = [{ label: "NVD public research", url: `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(subject)}&search_type=all` }, { label: "GitHub Advisory Database", url: `https://github.com/advisories?query=${encodeURIComponent(subject)}` }, { label: "CISA KEV research", url: googleSearch(`site:cisa.gov known exploited vulnerabilities "${subject}"`) }];
  const data = { subject, links, status: "manual public advisory pivots", limitation: "These are research links only. A product, organization, domain, or technology mention in an advisory does not establish version applicability, exposure, or exploitability." };
  const record = evidenceFinding("public-advisory-pivots", "Threat Intelligence", "Public advisory research pivots", `Prepared public advisory and KEV research pivots for ${subject}. Results require version-specific analyst validation.`, data, "low", 100, links[0].url, "lead", "review", [String(data.limitation)]);
  record.sourceCount = 0;
  return { findings: [record] };
}

export const passiveExpansionSafetyForTests = { blockedHost, privateIpv4, privateIpv6, rootDomain };
