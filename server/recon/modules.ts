import { resolve4, resolve6, resolveMx, resolveNs, resolveTxt, resolveCname, resolvePtr } from "node:dns/promises";
import tls from "node:tls";
import { load } from "cheerio";
import robotsParser from "robots-parser";
import { getDomain } from "tldts";
import { ENV } from "../_core/env";
import type { ModuleDefinition, ModuleResult, ReconFinding, ReconOptions, ReconTarget, RiskLevel } from "./types";
import { certificateTimeline, defensiveBrandLeads, emailDisclosureIntelligence, githubSupplyChain, historicalWebChange, networkOwnershipContext, publicAdvisoryPivots } from "./passiveExpansion";
import { publicUsernamePresence } from "./usernamePresence";
import { communityIntegrationStatus, consentBoundEmailPosture, onionIndexLeads, publicSocialProfileLinks } from "./identityModules";

const TIMEOUT_MS = 12_000;
const fetchText = async (url: string, init: RequestInit = {}) => {
  const response = await fetch(url, { ...init, headers: { "User-Agent": "ReconGPT/2.0 (passive-intelligence)", ...(init.headers || {}) }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.text();
};
const fetchJson = async <T>(url: string, init: RequestInit = {}) => JSON.parse(await fetchText(url, init)) as T;
const safe = async <T>(fallback: T, fn: () => Promise<T>) => { try { return await fn(); } catch { return fallback; } };
const uid = () => crypto.randomUUID().slice(0, 16);
const finding = (moduleId: string, category: string, title: string, summary: string, data: Record<string, unknown>, severity: RiskLevel = "low", confidence = 82, sourceUrl?: string): ReconFinding => ({ id: uid(), moduleId, category, title, summary, severity, confidence, data, sourceUrl });
const hostOf = (target: ReconTarget) => target.hostname || target.domain || target.normalized;
const isIPAddress = (value: string) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":");
const rootDomain = (hostname: string) => getDomain(hostname, { allowPrivateDomains: false }) || hostname.toLowerCase();
const query = (q: string) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;
const CRAWLER_AGENT = "ReconGPT/2.1 (authorized-public-research)";
const CRAWL_TIMEOUT_MS = 8_000;
const MAX_HTML_BYTES = 360_000;
const privateIpv4 = (value: string) => /^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[0-1])\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.1[89]\.|198\.51\.100\.|203\.0\.113\.|224\.|23\d\.|24\d\.|25[0-5]\.)/.test(value);
const privateIpv6 = (value: string) => /^(?:::1|fe[89ab]|f[cd]|::ffff:(?:0*:)?(?:127|10|192\.168)\.)/i.test(value);
const blockedHost = (hostname: string) => hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal") || hostname.endsWith(".test") || hostname.endsWith(".invalid");

function normalizedHttpUrl(value: string) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    parsed.hash = "";
    return parsed;
  } catch { return null; }
}

async function isSafePublicUrl(candidate: URL) {
  if (blockedHost(candidate.hostname)) return false;
  const addresses = await resolveHost(candidate.hostname);
  return addresses.length > 0 && addresses.every(address => !privateIpv4(address) && !privateIpv6(address));
}

async function readLimited(response: Response, maxBytes = MAX_HTML_BYTES) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < maxBytes) {
    const next = await reader.read();
    if (next.done) break;
    const take = Math.min(next.value.byteLength, maxBytes - total);
    chunks.push(next.value.slice(0, take));
    total += take;
    if (take < next.value.byteLength) break;
  }
  reader.cancel().catch(() => undefined);
  const bytes = new Uint8Array(total);
  let offset = 0;
  chunks.forEach(chunk => { bytes.set(chunk, offset); offset += chunk.byteLength; });
  return new TextDecoder().decode(bytes);
}

function flattenDuckDuckGoTopics(topics: unknown, collected: Array<{ title: string; url: string; text: string }>) {
  if (!Array.isArray(topics)) return;
  for (const topic of topics) {
    if (collected.length >= 12 || !topic || typeof topic !== "object") continue;
    const item = topic as { FirstURL?: unknown; Text?: unknown; Topics?: unknown };
    if (typeof item.FirstURL === "string" && typeof item.Text === "string") collected.push({ title: item.Text.slice(0, 180), url: item.FirstURL, text: item.Text.slice(0, 800) });
    else flattenDuckDuckGoTopics(item.Topics, collected);
  }
}

export const crawlerSafetyForTests = { normalizedHttpUrl, privateIpv4, privateIpv6, blockedHost, rootDomain };

async function resolveHost(hostname: string): Promise<string[]> {
  if (isIPAddress(hostname)) return [hostname];
  const [ipv4, ipv6] = await Promise.all([safe<string[]>([], () => resolve4(hostname)), safe<string[]>([], () => resolve6(hostname))]);
  return Array.from(new Set([...ipv4, ...ipv6]));
}

async function certificateFor(hostname: string) {
  return new Promise<Record<string, unknown>>((resolve, reject) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 9_000 }, () => {
      const cert = socket.getPeerCertificate(true) as tls.DetailedPeerCertificate;
      socket.end();
      resolve({ subject: cert.subject, issuer: cert.issuer, valid_from: cert.valid_from, valid_to: cert.valid_to, serialNumber: cert.serialNumber, fingerprint256: cert.fingerprint256, subjectaltname: cert.subjectaltname, ca: cert.ca });
    });
    socket.on("timeout", () => { socket.destroy(); reject(new Error("TLS connection timed out")); });
    socket.on("error", reject);
  });
}

async function crtSh(target: ReconTarget): Promise<ModuleResult> {
  const domain = rootDomain(hostOf(target));
  const rows = await fetchJson<Array<{ name_value?: string }>>(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`);
  const subdomains = Array.from(new Set(rows.flatMap(row => (row.name_value || "").split("\n")).map(value => value.trim().replace(/^\*\./, "").toLowerCase()).filter(value => value.endsWith(`.${domain}`) || value === domain))).sort();
  const record = finding("crt-subdomains", "Domain", `${subdomains.length} certificate-transparency names`, "Certificate Transparency records reveal publicly logged names associated with the target domain.", { domain, subdomains, total: subdomains.length }, "low", 94, `https://crt.sh/?q=%25.${domain}`);
  record.entities = subdomains.slice(0, 100).map(value => ({ type: value === domain ? "domain" : "subdomain", value, confidence: 94 }));
  return { findings: [record] };
}

async function dnsRecords(target: ReconTarget): Promise<ModuleResult> {
  const host = hostOf(target);
  const dkimSelectors = ["default", "selector1", "selector2", "google", "mail"];
  const [a, aaaa, mx, ns, txt, cname, dmarc, ...dkimResults] = await Promise.all([
    safe<string[]>([], () => resolve4(host)), safe<string[]>([], () => resolve6(host)), safe<Array<{ exchange: string; priority: number }>>([], () => resolveMx(host)), safe<string[]>([], () => resolveNs(host)), safe<string[][]>([], () => resolveTxt(host)), safe<string[]>([], () => resolveCname(host)), safe<string[][]>([], () => resolveTxt(`_dmarc.${host}`)),
    ...dkimSelectors.map(selector => safe<string[][]>([], () => resolveTxt(`${selector}._domainkey.${host}`))),
  ]);
  const spf = txt.map(value => value.join("")).filter(value => value.toLowerCase().startsWith("v=spf1"));
  const dmarcText = dmarc.map(value => value.join("")).filter(value => value.toLowerCase().startsWith("v=dmarc1"));
  const dkim = dkimResults.map((records, index) => ({ selector: dkimSelectors[index], records: records.map(record => record.join("")) })).filter(entry => entry.records.length > 0);
  const data = { host, a, aaaa, mx, ns, txt: txt.map(value => value.join("")), spf, dmarc: dmarcText, cname, dkim, dkimMethodNote: "ReconGPT checks common public selectors. Absence does not prove DKIM is not deployed; an organization may use another selector." };
  const record = finding("dns-posture", "Domain", "DNS and email-authentication posture", `Collected ${a.length + aaaa.length} address record(s), ${mx.length} MX record(s), and ${ns.length} nameserver(s).`, data, dmarcText.length === 0 ? "medium" : "low", 95, `https://dns.google/query?name=${host}`);
  record.entities = [...[...a, ...aaaa].map(value => ({ type: "ip" as const, value, confidence: 95 })), { type: "domain" as const, value: host, confidence: 96 }];
  return { findings: [record] };
}

async function dnsCrosscheck(target: ReconTarget): Promise<ModuleResult> {
  const host = hostOf(target);
  const recordTypes = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"];
  const responses = await Promise.all(recordTypes.map(async type => {
    try {
      const payload = await fetchJson<{ Status?: number; Answer?: Array<{ name?: string; type?: number; TTL?: number; data?: string }> }>(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`);
      return { type, status: payload.Status ?? null, answers: (payload.Answer || []).slice(0, 100).map(answer => ({ name: answer.name, type: answer.type, ttl: answer.TTL, data: answer.data })) };
    } catch (error) {
      return { type, status: null, answers: [], error: error instanceof Error ? error.message : "DNS-over-HTTPS unavailable" };
    }
  }));
  const unavailable = responses.filter(item => item.error).map(item => item.type);
  const answerCount = responses.reduce((sum, item) => sum + item.answers.length, 0);
  const record = finding("dns-crosscheck", "Domain", "Independent DNS-over-HTTPS cross-check", `Google Public DNS returned ${answerCount} public record answer(s) across ${recordTypes.length - unavailable.length}/${recordTypes.length} checked record type(s). Empty responses are not treated as an absence guarantee.`, { host, source: "Google Public DNS DoH", checks: responses, unavailableRecordTypes: unavailable, limitation: "DNS results are point-in-time and resolver-dependent; an empty response is not a conclusive absence claim." }, unavailable.length ? "medium" : "low", unavailable.length ? 72 : 93, `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`);
  record.entities = [{ type: "domain", value: host, confidence: 96 }];
  return { findings: [record], notices: unavailable.length ? [`DNS-over-HTTPS did not respond for: ${unavailable.join(", ")}.`] : undefined };
}

async function rdapWhois(target: ReconTarget): Promise<ModuleResult> {
  const host = rootDomain(hostOf(target));
  const data = await fetchJson<Record<string, unknown>>(`https://rdap.org/domain/${encodeURIComponent(host)}`);
  const events = Array.isArray(data.events) ? data.events : [];
  const record = finding("rdap-whois", "Domain", "RDAP registration intelligence", "Public RDAP registration metadata was collected for the registrable domain.", { domain: host, handle: data.handle, ldhName: data.ldhName, status: data.status, events, nameservers: data.nameservers, entities: data.entities }, "low", 91, `https://rdap.org/domain/${host}`);
  record.entities = [{ type: "domain", value: host, confidence: 92 }];
  return { findings: [record] };
}

async function tlsCertificate(target: ReconTarget): Promise<ModuleResult> {
  const host = hostOf(target);
  const data = await certificateFor(host);
  const expiry = data.valid_to ? new Date(String(data.valid_to)).getTime() - Date.now() : null;
  const severity: RiskLevel = expiry !== null && expiry < 30 * 86_400_000 ? "medium" : "low";
  const record = finding("tls-certificate", "Infrastructure", "TLS certificate profile", "Live TLS handshake captured the public certificate issuer, validity period, and subject alternative names.", data, severity, 96, `https://${host}`);
  const sans = String(data.subjectaltname || "").split(",").map(item => item.trim().replace(/^DNS:/, "")).filter(Boolean);
  const subject = data.subject as Record<string, unknown> | undefined;
  record.entities = [{ type: "certificate", value: String(data.fingerprint256 || host), label: String(subject?.CN || host), confidence: 96 }, ...sans.slice(0, 50).map(value => ({ type: "subdomain" as const, value, confidence: 93 }))];
  return { findings: [record] };
}

async function httpFingerprint(target: ReconTarget): Promise<ModuleResult> {
  const host = hostOf(target);
  const response = await fetch(`https://${host}`, { redirect: "follow", headers: { "User-Agent": "ReconGPT/2.0 (passive-intelligence)" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  const body = await response.text();
  const headers = Object.fromEntries(response.headers.entries());
  const tech = [
    ["Cloudflare", /cloudflare/i.test(headers.server || "") || /__cf|cf-ray/i.test(body)], ["WordPress", /wp-content|wp-includes/i.test(body)], ["React", /_next\/static|react/i.test(body)], ["Next.js", /_next\//i.test(body)], ["Google Analytics", /googletagmanager|google-analytics/i.test(body)], ["Bootstrap", /bootstrap(?:\.min)?\.css/i.test(body)], ["jQuery", /jquery(?:\.min)?\.js/i.test(body)], ["Shopify", /cdn\.shopify\.com|shopify-section/i.test(body)],
  ].filter(([, matches]) => matches).map(([name]) => name);
  const security = { hsts: Boolean(headers["strict-transport-security"]), csp: Boolean(headers["content-security-policy"]), frameOptions: Boolean(headers["x-frame-options"]), nosniff: Boolean(headers["x-content-type-options"]), referrerPolicy: Boolean(headers["referrer-policy"]) };
  const missing = Object.entries(security).filter(([, enabled]) => !enabled).map(([header]) => header);
  const data = { url: response.url, status: response.status, headers, technologies: tech, securityHeaders: security, cdnOrWafSignals: tech.includes("Cloudflare") ? ["Cloudflare"] : [], missingSecurityHeaders: missing };
  const record = finding("http-fingerprint", "Infrastructure", "HTTP posture and technology fingerprint", `The target returned HTTP ${response.status}; ${tech.length ? tech.join(", ") : "no strong framework signal"} was detected from public response metadata.`, data, missing.length >= 3 ? "medium" : "low", 88, response.url);
  record.entities = [{ type: "url", value: response.url, confidence: 96 }, { type: "domain", value: host, confidence: 94 }];
  return { findings: [record] };
}

async function passiveIpInfo(target: ReconTarget): Promise<ModuleResult> {
  const ip = target.type === "ip" ? target.normalized : (await resolveHost(hostOf(target)))[0];
  if (!ip) return { findings: [], notices: ["No public IP could be resolved for IP intelligence."] };
  if (!ENV.ipinfoToken) return { findings: [], notices: ["IPinfo module is configured but its server-side token is not available."] };
  const data = await fetchJson<Record<string, unknown>>(`https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(ENV.ipinfoToken)}`);
  const record = finding("ipinfo", "IP Intelligence", "IP geolocation and ASN", "IPinfo returned public network ownership and geolocation metadata.", data, "low", 91, `https://ipinfo.io/${ip}`);
  record.entities = [{ type: "ip", value: ip, confidence: 98 }, ...(data.org ? [{ type: "asn" as const, value: String(data.org), confidence: 88 }] : [])];
  return { findings: [record] };
}

async function ptrLookup(target: ReconTarget): Promise<ModuleResult> {
  const ip = target.type === "ip" ? target.normalized : (await resolveHost(hostOf(target)))[0];
  if (!ip) return { findings: [] };
  const ptr = await safe<string[]>([], () => resolvePtr(ip));
  const record = finding("reverse-ptr", "IP Intelligence", "Reverse DNS resolution", ptr.length ? `PTR records associate ${ip} with ${ptr.length} public hostname(s).` : "No PTR records were returned for the resolved IP.", { ip, ptr }, "low", 95);
  record.entities = [{ type: "ip", value: ip, confidence: 98 }, ...ptr.map(value => ({ type: "subdomain" as const, value, confidence: 95 }))];
  return { findings: [record] };
}

async function routedPrefix(target: ReconTarget): Promise<ModuleResult> {
  const ip = target.type === "ip" ? target.normalized : (await resolveHost(hostOf(target)))[0];
  if (!ip) return { findings: [], notices: ["No public IP could be resolved for routed-prefix intelligence."] };
  const response = await fetchJson<{ data?: { prefix?: string; asns?: number[]; holder?: string } }>(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`);
  const data = response.data || {};
  const asns = Array.isArray(data.asns) ? data.asns.map(value => `AS${value}`) : [];
  const record = finding("routed-prefix", "IP Intelligence", "Passive BGP prefix and network ownership", `RIPEstat returned public routed-prefix context${data.prefix ? ` for ${data.prefix}` : ""} associated with ${ip}. This is registry/routing intelligence, not active reachability testing.`, { ip, prefix: data.prefix || null, asns, holder: data.holder || null }, "low", 93, `https://stat.ripe.net/${ip}`);
  record.entities = [{ type: "ip", value: ip, confidence: 98 }, ...asns.map(value => ({ type: "asn" as const, value, confidence: 93 }))];
  return { findings: [record] };
}

async function abuseIpdb(target: ReconTarget): Promise<ModuleResult> {
  const ip = target.type === "ip" ? target.normalized : (await resolveHost(hostOf(target)))[0];
  if (!ip || !ENV.abuseIpdbApiKey) return { findings: [], notices: ["AbuseIPDB is unavailable until its server-only provider key is configured."] };
  const data = await fetchJson<{ data: Record<string, unknown> }>(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`, { headers: { Key: ENV.abuseIpdbApiKey, Accept: "application/json" } });
  const score = Number(data.data.abuseConfidenceScore || 0);
  const severity: RiskLevel = score >= 75 ? "high" : score >= 25 ? "medium" : "low";
  const record = finding("abuseipdb", "IP Intelligence", "AbuseIPDB reputation signal", `AbuseIPDB reports an abuse-confidence score of ${score}% for this IP over the configured lookback window.`, data.data, severity, 90, `https://www.abuseipdb.com/check/${ip}`);
  record.entities = [{ type: "ip", value: ip, confidence: 98 }];
  return { findings: [record] };
}

async function shodan(target: ReconTarget): Promise<ModuleResult> {
  const ip = target.type === "ip" ? target.normalized : (await resolveHost(hostOf(target)))[0];
  if (!ip || !ENV.shodanApiKey) return { findings: [], notices: ["Shodan is unavailable until its server-only provider key is configured."] };
  const data = await fetchJson<Record<string, unknown>>(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(ENV.shodanApiKey)}`);
  const ports = Array.isArray(data.ports) ? data.ports : [];
  const record = finding("shodan", "IP Intelligence", "Shodan observed-service intelligence", `Shodan has ${ports.length} historically observed port(s) for this public IP. This is passive third-party scan data, not a new scan.`, data, ports.length > 8 ? "medium" : "low", 88, `https://www.shodan.io/host/${ip}`);
  record.entities = [{ type: "ip", value: ip, confidence: 98 }];
  return { findings: [record] };
}

async function virusTotal(target: ReconTarget): Promise<ModuleResult> {
  if (!ENV.virustotalApiKey) return { findings: [], notices: ["VirusTotal is unavailable until its server-only provider key is configured."] };
  const identifier = target.type === "ip" ? target.normalized : rootDomain(hostOf(target));
  const kind = target.type === "ip" ? "ip_addresses" : "domains";
  const data = await fetchJson<{ data: { attributes: Record<string, unknown> } }>(`https://www.virustotal.com/api/v3/${kind}/${encodeURIComponent(identifier)}`, { headers: { "x-apikey": ENV.virustotalApiKey } });
  const stats = data.data.attributes.last_analysis_stats as Record<string, number> | undefined;
  const malicious = Number(stats?.malicious || 0);
  const severity: RiskLevel = malicious >= 5 ? "high" : malicious > 0 ? "medium" : "low";
  const record = finding("virustotal", "Threat Intelligence", "VirusTotal reputation consensus", `VirusTotal's latest analysis consensus includes ${malicious} malicious verdict(s).`, data.data.attributes, severity, 89, `https://www.virustotal.com/gui/${target.type === "ip" ? "ip-address" : "domain"}/${identifier}`);
  record.entities = [{ type: target.type === "ip" ? "ip" : "domain", value: identifier, confidence: 96 }];
  return { findings: [record] };
}

async function urlscan(target: ReconTarget): Promise<ModuleResult> {
  const domain = rootDomain(hostOf(target));
  const headers = ENV.urlscanApiKey ? { "API-Key": ENV.urlscanApiKey } : undefined;
  const data = await fetchJson<{ results?: unknown[] }>(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}`, { headers });
  const results = data.results || [];
  const record = finding("urlscan", "Web Intelligence", "urlscan.io public scan history", `urlscan.io returned ${results.length} public scan result(s) for this domain query.`, { domain, total: results.length, results: results.slice(0, 15) }, "low", 84, `https://urlscan.io/search/#domain:${domain}`);
  record.entities = [{ type: "domain", value: domain, confidence: 94 }];
  return { findings: [record] };
}

async function wayback(target: ReconTarget): Promise<ModuleResult> {
  const domain = rootDomain(hostOf(target));
  const rows = await fetchJson<string[][]>(`https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=timestamp,original,statuscode,mimetype&filter=statuscode:200&collapse=urlkey&limit=250`);
  const records = rows.slice(1).map(row => ({ timestamp: row[0], url: row[1], status: row[2], mimeType: row[3] }));
  const documents = records.filter(row => /\.(pdf|docx?|xlsx?|csv|pptx?|json|xml|txt|log)$/i.test(row.url));
  const record = finding("wayback", "Historical", "Wayback Machine URL history", `The Internet Archive returned ${records.length} historical successful URL(s), including ${documents.length} document-like URL(s).`, { domain, records: records.slice(0, 100), documentUrls: documents.slice(0, 50), total: records.length }, "low", 92, `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json`);
  record.entities = [{ type: "domain", value: domain, confidence: 95 }, ...records.slice(0, 40).map(row => ({ type: "url" as const, value: row.url, confidence: 91 }))];
  return { findings: [record] };
}

async function commonCrawl(target: ReconTarget): Promise<ModuleResult> {
  const domain = rootDomain(hostOf(target));
  const indexes = await fetchJson<Array<{ id?: string; "cdx-api"?: string }>>("https://index.commoncrawl.org/collinfo.json");
  const latest = indexes.find(index => index["cdx-api"]);
  const endpoint = latest?.["cdx-api"];
  if (!endpoint) return { findings: [], notices: ["Common Crawl did not publish an available index endpoint."] };
  const raw = await fetchText(`${endpoint}?url=*.${encodeURIComponent(domain)}/*&output=json&filter=status:200&collapse=urlkey&limit=250`);
  const rows = raw.split("\n").filter(Boolean).slice(0, 250).flatMap(line => {
    try {
      const item = JSON.parse(line) as Record<string, unknown>;
      return [{ url: String(item.url || ""), timestamp: String(item.timestamp || ""), mime: String(item.mime || ""), status: String(item.status || ""), digest: String(item.digest || "") }];
    } catch { return []; }
  }).filter(item => item.url);
  const documentUrls = rows.filter(item => /\.(pdf|docx?|xlsx?|csv|pptx?|json|xml|txt|log)(?:\?|$)/i.test(item.url));
  const record = finding("common-crawl", "Historical", "Common Crawl public-web index", `Common Crawl's latest public index returned ${rows.length} deduplicated historical URL record(s), including ${documentUrls.length} document-like URL(s). Indexed URLs are historical references, not a claim that content remains available.`, { domain, index: latest?.id || "latest", indexEndpoint: endpoint, total: rows.length, records: rows.slice(0, 150), documentUrls: documentUrls.slice(0, 60), limitation: "Common Crawl index entries are passive historical metadata. ReconGPT does not retrieve page bodies or restricted content from the archive." }, "low", 89, `${endpoint}?url=*.${encodeURIComponent(domain)}/*&output=json`);
  record.entities = [{ type: "domain", value: domain, confidence: 95 }, ...rows.slice(0, 50).map(item => ({ type: "url" as const, value: item.url, confidence: 88 }))];
  return { findings: [record] };
}

async function dorkBuilder(target: ReconTarget, options: ReconOptions): Promise<ModuleResult> {
  const anchor = target.type === "company" ? `"${target.normalized}"` : `site:${rootDomain(hostOf(target))}`;
  const base = [`${anchor} filetype:pdf`, `${anchor} filetype:xlsx`, `${anchor} inurl:login`, `${anchor} intitle:admin`, `${anchor} (filetype:env OR filetype:log)`, `${anchor} (backup OR archive OR database)`];
  const queries = options.dorkIntensity === "focused" ? base.slice(0, 2) : options.dorkIntensity === "balanced" ? base.slice(0, 4) : base;
  const engines = queries.flatMap(value => ([{ engine: "Google", query: value, url: query(value) }, { engine: "Bing", query: value, url: `https://www.bing.com/search?q=${encodeURIComponent(value)}` }, { engine: "DuckDuckGo", query: value, url: `https://duckduckgo.com/?q=${encodeURIComponent(value)}` }]));
  return { findings: [finding("research-dorks", "Research", "Analyst search-query workspace", "Generated passive research queries. These links open public search engines; ReconGPT does not scrape them or access restricted content.", { intensity: options.dorkIntensity, queries, engines }, "low", 100)] };
}

async function publicWebSurface(target: ReconTarget): Promise<ModuleResult> {
  const host = hostOf(target);
  const [robots, sitemap, security] = await Promise.all([safe<string>("", () => fetchText(`https://${host}/robots.txt`)), safe<string>("", () => fetchText(`https://${host}/sitemap.xml`)), safe<string>("", () => fetchText(`https://${host}/.well-known/security.txt`))]);
  const snippet = (value: string) => value.slice(0, 8_000);
  const publicUrls = [`https://${host}/robots.txt`, `https://${host}/sitemap.xml`, `https://${host}/.well-known/security.txt`];
  const data = { host, robots: { available: Boolean(robots), content: snippet(robots) }, sitemap: { available: Boolean(sitemap), content: snippet(sitemap) }, securityTxt: { available: Boolean(security), content: snippet(security) }, publicUrls };
  const record = finding("public-web-surface", "Web Intelligence", "Public web-surface manifests", `Collected public robots.txt, sitemap.xml, and security.txt availability for ${host}. These standard web resources may aid authorized asset inventory but do not establish exposure on their own.`, data, "low", 94, `https://${host}/robots.txt`);
  record.entities = [{ type: "domain", value: rootDomain(host), confidence: 96 }, ...publicUrls.map(value => ({ type: "url" as const, value, confidence: 94 }))];
  return { findings: [record] };
}

async function documentMetadata(target: ReconTarget): Promise<ModuleResult> {
  const url = target.normalized;
  const response = await fetch(url, { method: "HEAD", redirect: "follow", headers: { "User-Agent": "ReconGPT/2.0 (passive-intelligence)" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  const headers = Object.fromEntries(response.headers.entries());
  const record = finding("document-metadata", "Document Intelligence", "Public document HTTP metadata", "Collected metadata exposed by the public HTTP response only; ReconGPT did not download, OCR, or execute the document.", { requestedUrl: url, finalUrl: response.url, status: response.status, contentType: headers["content-type"] || "unknown", contentLength: headers["content-length"] || "unknown", lastModified: headers["last-modified"] || null, contentDisposition: headers["content-disposition"] || null, etag: headers.etag || null, headers }, "low", 96, response.url);
  record.entities = [{ type: "url", value: response.url, confidence: 98 }];
  return { findings: [record] };
}

async function exposureResearch(target: ReconTarget, options: ReconOptions): Promise<ModuleResult> {
  const domain = rootDomain(hostOf(target));
  const searchTerms = [`site:pastebin.com "${domain}"`, `site:github.com "${domain}"`, `site:gitlab.com "${domain}"`, `site:codeberg.org "${domain}"`, `"${domain}" ("security.txt" OR "responsible disclosure")`];
  const limitedTerms = options.dorkIntensity === "focused" ? searchTerms.slice(0, 2) : options.dorkIntensity === "balanced" ? searchTerms.slice(0, 4) : searchTerms;
  const pivots = limitedTerms.flatMap(term => [{ engine: "Google", query: term, url: query(term) }, { engine: "Bing", query: term, url: `https://www.bing.com/search?q=${encodeURIComponent(term)}` }, { engine: "DuckDuckGo", query: term, url: `https://duckduckgo.com/?q=${encodeURIComponent(term)}` }]);
  const githubCodeSearch = `https://github.com/search?type=code&q=${encodeURIComponent(`"${domain}"`)}`;
  return { findings: [finding("exposure-research", "Research", "Public exposure and paste research pivots", "Prepared manual public-search pivots for previously indexed references, code-hosting mentions, GitHub code search, and paste-site mentions. ReconGPT does not authenticate to, scrape, or attempt to retrieve restricted leak content.", { domain, intensity: options.dorkIntensity, pivots, githubCodeSearch, limitation: "A search result, mention, or historic paste URL is not evidence that a current credential or data exposure is valid." }, "low", 100, githubCodeSearch)] };
}

const USERNAME_PLATFORMS = ["github.com","gitlab.com","bitbucket.org","codeberg.org","reddit.com","x.com","twitter.com","instagram.com","facebook.com","threads.net","tiktok.com","youtube.com","twitch.tv","kick.com","linkedin.com","pinterest.com","tumblr.com","mastodon.social","bsky.app","medium.com","dev.to","hashnode.com","behance.net","dribbble.com","deviantart.com","flickr.com","vimeo.com","soundcloud.com","bandcamp.com","spotify.com","last.fm","goodreads.com","letterboxd.com","steamcommunity.com","xbox.com","playstation.com","epicgames.com","chess.com","lichess.org","duolingo.com","strava.com","fitbit.com","garmin.com","keybase.io","discord.com","telegram.me","vk.com","weibo.com","quora.com","stackoverflow.com","superuser.com","serverfault.com","producthunt.com","huggingface.co","kaggle.com","npmjs.com","pypi.org","rubygems.org","crates.io","packagist.org","docker.com","tryhackme.com","hackthebox.com","bugcrowd.com","hackerone.com","patreon.com","ko-fi.com","buymeacoffee.com","substack.com","wattpad.com","archiveofourown.org","fanfiction.net","wikidot.com","fandom.com","slack.com","notion.site","about.me","gravatar.com","disqus.com","meetup.com","eventbrite.com","tripadvisor.com","airbnb.com","etsy.com","ebay.com","amazon.com","imdb.com","myanimelist.net","anilist.co","discogs.com","reverbnation.com","mixcloud.com","dailymotion.com","rumble.com","odysee.com","snapchat.com","whatsapp.com","signal.org","skype.com","venmo.com","cash.app","paypal.com"];

async function usernameProfiles(target: ReconTarget, options: ReconOptions): Promise<ModuleResult> {
  const username = target.normalized.replace(/^@/, "");
  const limit = options.dorkIntensity === "focused" ? 36 : options.dorkIntensity === "balanced" ? 72 : USERNAME_PLATFORMS.length;
  const candidates = USERNAME_PLATFORMS.slice(0, limit).map(platform => ({ platform, url: `https://${platform}/${encodeURIComponent(username)}` }));
  const [github, repositories, gists] = await Promise.all([
    safe<Record<string, unknown> | null>(null, () => fetchJson(`https://api.github.com/users/${encodeURIComponent(username)}`, { headers: { Accept: "application/vnd.github+json" } })),
    safe<Array<Record<string, unknown>>>([], () => fetchJson(`https://api.github.com/users/${encodeURIComponent(username)}/repos?per_page=100&sort=updated`, { headers: { Accept: "application/vnd.github+json" } })),
    safe<Array<Record<string, unknown>>>([], () => fetchJson(`https://api.github.com/users/${encodeURIComponent(username)}/gists?per_page=100`, { headers: { Accept: "application/vnd.github+json" } })),
  ]);
  const findings = [finding("username-matrix", "Identity", "Cross-platform username research matrix", `Prepared ${candidates.length} public profile candidates across an analyst-curated platform matrix. Presence must be verified by the analyst; a URL alone is not a confirmed identity match.`, { username, candidates, platformCount: USERNAME_PLATFORMS.length }, "low", 100)];
  if (github && !("message" in github)) {
    const githubFinding = finding("github-public", "Identity", "Public GitHub profile, repositories, and gists", "GitHub's public API returned public account metadata together with visible repository and gist indexes. No private data or authentication bypass is used.", { profile: github, repositories: repositories.slice(0, 50).map(repo => ({ name: repo.name, description: repo.description, html_url: repo.html_url, updated_at: repo.updated_at, language: repo.language, stargazers_count: repo.stargazers_count })), gists: gists.slice(0, 50).map(gist => ({ id: gist.id, description: gist.description, html_url: gist.html_url, created_at: gist.created_at, updated_at: gist.updated_at, public: gist.public })) }, "low", 98, `https://github.com/${username}`);
    githubFinding.entities = [{ type: "username", value: username, confidence: 98 }, { type: "url", value: `https://github.com/${username}`, confidence: 98 }];
    findings.push(githubFinding);
  }
  return { findings };
}

async function emailPosture(target: ReconTarget): Promise<ModuleResult> {
  const [local, domain] = target.normalized.split("@");
  const dns = await dnsRecords({ ...target, type: "domain", normalized: domain, hostname: domain, domain });
  const candidates = ["info", "contact", "security", "support", "abuse", "privacy", "postmaster"].map(localPart => `${localPart}@${domain}`);
  const record = finding("email-context", "Identity", "Email address context and public discovery pivots", "Email intelligence is limited to domain authentication posture, role-address candidates, and public research links; no mailbox access, SMTP probing, or credential guessing is performed.", { email: target.normalized, localPartPattern: local.replace(/[a-z]/gi, "a").replace(/[0-9]/g, "0"), roleAddressCandidates: candidates, candidateStatus: "unverified; candidates are research pivots, not evidence of mailboxes", breachCheckUrl: `https://haveibeenpwned.com/account/${encodeURIComponent(target.normalized)}`, publicResearch: [query(`"${target.normalized}"`), query(`"${target.normalized}" site:github.com`)] }, "low", 96);
  record.entities = [{ type: "email", value: target.normalized, confidence: 100 }, { type: "domain", value: domain, confidence: 100 }];
  return { findings: [record, ...dns.findings] };
}

async function corporateLinks(target: ReconTarget): Promise<ModuleResult> {
  const company = target.normalized;
  const links = [{ label: "Google company search", url: query(`"${company}"`) }, { label: "OpenCorporates", url: `https://opencorporates.com/companies?q=${encodeURIComponent(company)}` }, { label: "Google Jobs/Careers cues", url: query(`"${company}" (careers OR jobs OR hiring)`) }, { label: "Trademark research", url: `https://tmsearch.uspto.gov/search/search-information?query=${encodeURIComponent(company)}` }, { label: "Partners & vendors", url: query(`"${company}" (partner OR vendor OR customer OR integration)`) }, { label: "Press & acquisition research", url: query(`"${company}" (acquired OR partnership OR funding OR press release)`) }];
  const record = finding("corporate-research", "Corporate", "Corporate intelligence research links", "Prepared public-registry, hiring, trademark, partnership, vendor, and press research pivots for analyst review. The organization node is an analyst-supplied target; research pivots are not asserted relationships.", { company, links }, "low", 100, links[1].url);
  record.entities = [{ type: "organization", value: company, label: company, confidence: 100, metadata: { targetSupplied: true } }];
  return { findings: [record] };
}

async function phoneResearch(target: ReconTarget): Promise<ModuleResult> {
  const phone = target.normalized;
  const queries = [`"${phone}"`, `"${phone}" (contact OR support OR business)`, `"${phone}" site:github.com`];
  const record = finding("phone-research", "Identity", "Public phone-number research workspace", "Prepared non-enriching public-search pivots for analyst review. ReconGPT does not perform caller-ID enrichment, messaging, SIM lookup, or carrier account access.", { phone, publicResearch: queries.flatMap(value => [{ engine: "Google", url: query(value) }, { engine: "Bing", url: `https://www.bing.com/search?q=${encodeURIComponent(value)}` }, { engine: "DuckDuckGo", url: `https://duckduckgo.com/?q=${encodeURIComponent(value)}` }]), limitation: "Public search mentions do not prove ownership or current association." }, "low", 100);
  record.entities = [{ type: "phone", value: phone, confidence: 100 }];
  return { findings: [record] };
}

async function asnResearch(target: ReconTarget): Promise<ModuleResult> {
  const asn = target.normalized.toUpperCase();
  const record = finding("asn-research", "IP Intelligence", "ASN and routing research pivots", "Prepared passive routing, registry, and peering research links for this autonomous-system number. These sources represent public routing or registry context, not a direct ownership assertion.", { asn, links: [{ label: "Hurricane Electric BGP", url: `https://bgp.he.net/${encodeURIComponent(asn)}` }, { label: "PeeringDB", url: `https://www.peeringdb.com/search?q=${encodeURIComponent(asn)}` }, { label: "Google research", url: query(`"${asn}" (network OR BGP OR routing)`) }, { label: "RIPEstat", url: `https://stat.ripe.net/${encodeURIComponent(asn)}` }] }, "low", 100);
  record.entities = [{ type: "asn", value: asn, confidence: 100 }];
  return { findings: [record] };
}

async function publicSearchDiscovery(target: ReconTarget): Promise<ModuleResult> {
  const subject = target.type === "company" ? target.normalized : hostOf(target);
  const searchQuery = target.type === "company" ? `"${subject}"` : `site:${subject}`;
  const payload = await fetchJson<{ AbstractText?: string; AbstractURL?: string; AbstractSource?: string; RelatedTopics?: unknown }>(`https://api.duckduckgo.com/?q=${encodeURIComponent(searchQuery)}&format=json&no_html=1&no_redirect=1`);
  const related: Array<{ title: string; url: string; text: string }> = [];
  flattenDuckDuckGoTopics(payload.RelatedTopics, related);
  const direct = payload.AbstractText && payload.AbstractURL ? [{ title: String(payload.AbstractSource || "DuckDuckGo instant answer"), url: payload.AbstractURL, text: payload.AbstractText.slice(0, 800) }] : [];
  const results = [...direct, ...related].slice(0, 12);
  const record = finding("public-search", "Research", "Free public search discovery", `DuckDuckGo's no-key public instant-answer endpoint returned ${results.length} structured result(s) for an exact target-scoped query. This is a constrained discovery source, not a claim of complete search-engine coverage.`, { query: searchQuery, provider: "DuckDuckGo Instant Answer API", results, analystSearchLinks: [{ engine: "DuckDuckGo", url: `https://duckduckgo.com/?q=${encodeURIComponent(searchQuery)}` }, { engine: "Bing", url: `https://www.bing.com/search?q=${encodeURIComponent(searchQuery)}` }, { engine: "Google", url: query(searchQuery) }], limitation: "General web-index rankings, personal data, login-gated pages, and search-engine-only results may be absent. Use the linked public searches for analyst review." }, "low", results.length ? 78 : 62, `https://api.duckduckgo.com/?q=${encodeURIComponent(searchQuery)}`);
  record.entities = results.slice(0, 12).map(result => ({ type: "url" as const, value: result.url, confidence: 72 }));
  return { findings: [record], notices: results.length ? undefined : ["The free structured search source returned no direct result. Analyst-search links are provided as coverage pivots."] };
}

async function robotsAwareCrawl(target: ReconTarget, options: ReconOptions): Promise<ModuleResult> {
  const start = normalizedHttpUrl(target.type === "url" ? target.normalized : `https://${hostOf(target)}`);
  if (!start || !(await isSafePublicUrl(start))) return { findings: [], notices: ["Public-web crawl skipped because the target URL could not be validated as a public HTTP(S) destination."] };
  const origin = start.origin;
  const robotsUrl = new URL("/robots.txt", origin).toString();
  let robotsText = "";
  try { robotsText = await fetchText(robotsUrl, { headers: { "User-Agent": CRAWLER_AGENT }, signal: AbortSignal.timeout(CRAWL_TIMEOUT_MS) }); }
  catch { return { findings: [], notices: ["Public-web crawl skipped because robots.txt was unavailable. ReconGPT uses strict robots-aware collection and does not crawl when policy cannot be read."] }; }
  const robots = robotsParser(robotsUrl, robotsText);
  const maxPages = options.dorkIntensity === "deep" ? 12 : options.dorkIntensity === "balanced" ? 6 : 3;
  const maxDepth = options.dorkIntensity === "deep" ? 2 : 1;
  const queue: Array<{ url: string; depth: number }> = [{ url: start.toString(), depth: 0 }];
  const seen = new Set<string>();
  const pages: Array<Record<string, unknown>> = [];
  const skipped: Array<{ url: string; reason: string }> = [];
  while (queue.length && pages.length < maxPages) {
    const next = queue.shift()!;
    if (seen.has(next.url)) continue;
    seen.add(next.url);
    const pageUrl = normalizedHttpUrl(next.url);
    if (!pageUrl || pageUrl.origin !== origin || !(await isSafePublicUrl(pageUrl))) { skipped.push({ url: next.url, reason: "outside allowed public same-origin scope" }); continue; }
    if (robots.isAllowed(pageUrl.toString(), CRAWLER_AGENT) === false) { skipped.push({ url: pageUrl.toString(), reason: "disallowed by robots.txt" }); continue; }
    let response: Response;
    try { response = await fetch(pageUrl, { redirect: "manual", headers: { "User-Agent": CRAWLER_AGENT, Accept: "text/html,application/xhtml+xml" }, signal: AbortSignal.timeout(CRAWL_TIMEOUT_MS) }); }
    catch (error) { skipped.push({ url: pageUrl.toString(), reason: error instanceof Error ? error.message : "request failed" }); continue; }
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location"); const redirected = location ? normalizedHttpUrl(new URL(location, pageUrl).toString()) : null;
      if (redirected && redirected.origin === origin) queue.unshift({ url: redirected.toString(), depth: next.depth }); else skipped.push({ url: pageUrl.toString(), reason: "redirect left the permitted same-origin scope" });
      continue;
    }
    const contentType = response.headers.get("content-type") || "";
    if (!response.ok || !/text\/html|application\/xhtml\+xml/i.test(contentType)) { skipped.push({ url: pageUrl.toString(), reason: `unsupported response (${response.status}, ${contentType || "unknown content type"})` }); continue; }
    const html = await readLimited(response);
    const $ = load(html);
    const canonical = $("link[rel='canonical']").attr("href") || null;
    const links = Array.from(new Set($("a[href]").map((_, element) => $(element).attr("href") || "").get().map(href => normalizedHttpUrl(new URL(href, pageUrl).toString())).filter((link): link is URL => Boolean(link && link.origin === origin)).map(link => link.toString()))).slice(0, 80);
    const title = $("title").first().text().replace(/\s+/g, " ").trim().slice(0, 240);
    const description = $("meta[name='description']").attr("content")?.replace(/\s+/g, " ").trim().slice(0, 480) || null;
    const headings = $("h1,h2").map((_, element) => $(element).text().replace(/\s+/g, " ").trim()).get().filter(Boolean).slice(0, 12);
    const textPreview = $("body").text().replace(/\s+/g, " ").trim().slice(0, 1_400);
    pages.push({ url: pageUrl.toString(), status: response.status, title, description, canonical, headings, textPreview, outgoingSameOriginLinks: links.slice(0, 30), truncatedAtBytes: html.length >= MAX_HTML_BYTES });
    if (next.depth < maxDepth) links.slice(0, 50).forEach(link => { if (!seen.has(link) && queue.length < maxPages * 8) queue.push({ url: link, depth: next.depth + 1 }); });
  }
  const record = finding("public-web-crawl", "Web Intelligence", "Robots-aware public-web crawl", `Reviewed ${pages.length}/${maxPages} publicly reachable same-origin HTML page(s) at maximum depth ${maxDepth}. The crawler only performs bounded GET requests, honors robots exclusions, and does not authenticate, submit forms, or follow cross-origin links.`, { startUrl: start.toString(), crawlPolicy: { userAgent: CRAWLER_AGENT, robotsUrl, maxPages, maxDepth, maxHtmlBytesPerPage: MAX_HTML_BYTES, concurrency: 1, allowedOrigin: origin, denied: ["private or reserved network destinations", "cross-origin redirects and links", "authentication flows", "form submission", "non-HTML content"] }, pages, skipped: skipped.slice(0, 60), skippedCount: skipped.length, remainingQueueCount: queue.length, limitation: "This is a bounded public HTML sample, not an exhaustive site map or Internet-wide collection." }, "low", pages.length ? 88 : 65, start.toString());
  record.entities = pages.map(page => ({ type: "url" as const, value: String(page.url), confidence: 92 }));
  return { findings: [record], notices: skipped.length ? [`Crawl skipped ${skipped.length} URL(s); see the finding for robots, scope, response-type, and request-failure reasons.`] : undefined };
}

type PublicEndpointCheck = {
  path: string;
  status: number | null;
  contentType: string | null;
  redirected: boolean;
  sameOrigin: boolean;
  bytesRead: number;
  preview?: string;
  error?: string;
};

async function boundedSameOriginGet(origin: URL, path: string, includePreview = false): Promise<PublicEndpointCheck> {
  const url = new URL(path, origin);
  try {
    const response = await fetch(url, {
      redirect: "manual",
      headers: { "User-Agent": "ReconGPT/2.3 (bounded-public-provenance)", Accept: "text/plain,text/html,application/json,application/xml,text/xml;q=0.9,*/*;q=0.2" },
      signal: AbortSignal.timeout(CRAWL_TIMEOUT_MS),
    });
    const location = response.headers.get("location");
    const redirected = response.status >= 300 && response.status < 400;
    const redirectUrl = location ? normalizedHttpUrl(new URL(location, url).toString()) : null;
    const sameOrigin = !redirected || Boolean(redirectUrl && redirectUrl.origin === origin.origin);
    const contentType = response.headers.get("content-type");
    const content = response.ok && includePreview ? await readLimited(response, 24_000) : "";
    return {
      path,
      status: response.status,
      contentType,
      redirected,
      sameOrigin,
      bytesRead: content.length,
      preview: content ? content.replace(/\s+/g, " ").trim().slice(0, 520) : undefined,
    };
  } catch (error) {
    return { path, status: null, contentType: null, redirected: false, sameOrigin: true, bytesRead: 0, error: error instanceof Error ? error.message : "request failed" };
  }
}

async function publicPolicySurface(target: ReconTarget, options: ReconOptions): Promise<ModuleResult> {
  const base = normalizedHttpUrl(target.type === "url" ? target.normalized : `https://${hostOf(target)}`);
  if (!base || !(await isSafePublicUrl(base))) {
    return { findings: [], notices: ["Public policy checks were skipped because the target did not resolve to a permitted public web destination."] };
  }
  const budget = options.dorkIntensity === "focused" ? 3 : options.dorkIntensity === "deep" ? 6 : 5;
  const policyEndpoints: Array<[string, boolean]> = [
    ["/.well-known/security.txt", true],
    ["/security.txt", true],
    ["/robots.txt", true],
    ["/sitemap.xml", false],
    ["/manifest.json", false],
    ["/.well-known/assetlinks.json", false],
  ];
  const checks = await Promise.all(policyEndpoints.slice(0, budget).map(([path, preview]) => boundedSameOriginGet(base, path, preview)));
  const reachable = checks.filter(check => check.status !== null && check.status >= 200 && check.status < 300 && check.sameOrigin);
  const securityText = checks.find(check => check.path.includes("security.txt") && check.status === 200 && check.sameOrigin);
  const record = finding(
    "public-policy-surface",
    "Web Intelligence",
    "Public policy and release-signal surface",
    `Checked ${checks.length} bounded, same-origin public policy or application-descriptor endpoint(s); ${reachable.length} responded successfully${securityText ? ", including a security.txt disclosure channel" : ""}.`,
    {
      origin: base.origin,
      checks,
      requestPolicy: {
        maxRequests: budget,
        methods: ["GET"],
        redirects: "manual; cross-origin redirects are not followed",
        excluded: ["authentication", "forms", "state-changing endpoints", "private/reserved destinations", "downloads", "directory enumeration"],
      },
      sourceHealth: {
        attempted: checks.length,
        successful: reachable.length,
        unavailable: checks.filter(check => check.status === null).length,
        restrictedOrRedirected: checks.filter(check => !check.sameOrigin || check.status === 401 || check.status === 403 || check.status === 429).length,
      },
      limitation: "Endpoint availability is a point-in-time public observation. Missing or inaccessible documents are not proof that a policy, disclosure process, or release practice does not exist.",
    },
    securityText ? "low" : "medium",
    reachable.length ? 87 : 62,
    base.toString(),
  );
  record.entities = [{ type: "url", value: base.origin, confidence: 96 }];
  return { findings: [record], notices: checks.filter(check => check.status === 401 || check.status === 403 || check.status === 429).length ? ["Some public policy endpoints restricted automated access and were not retried."] : undefined };
}

function jsonLdSummary(value: unknown) {
  const entries = Array.isArray(value) ? value : value && typeof value === "object" ? [value] : [];
  return entries.slice(0, 24).map(entry => {
    const record = entry as Record<string, unknown>;
    const types = Array.isArray(record["@type"]) ? record["@type"] : [record["@type"]].filter(Boolean);
    return { type: types.map(String).slice(0, 6), id: typeof record["@id"] === "string" ? record["@id"].slice(0, 240) : undefined, url: typeof record.url === "string" ? record.url.slice(0, 240) : undefined, sameAsCount: Array.isArray(record.sameAs) ? record.sameAs.length : 0 };
  });
}

async function structuredWebProvenance(target: ReconTarget): Promise<ModuleResult> {
  const base = normalizedHttpUrl(target.type === "url" ? target.normalized : `https://${hostOf(target)}`);
  if (!base || !(await isSafePublicUrl(base))) return { findings: [], notices: ["Structured-web provenance was skipped because the target did not resolve to a permitted public web destination."] };
  const response = await fetch(base, { redirect: "manual", headers: { "User-Agent": "ReconGPT/2.3 (bounded-structured-web)", Accept: "text/html,application/xhtml+xml" }, signal: AbortSignal.timeout(CRAWL_TIMEOUT_MS) });
  if (!response.ok || !/text\/html|application\/xhtml\+xml/i.test(response.headers.get("content-type") || "")) return { findings: [], notices: [`Structured-web provenance was unavailable (${response.status}).`] };
  const html = await readLimited(response, 180_000);
  const $ = load(html);
  const jsonLd = $("script[type='application/ld+json']").map((_, node) => {
    try { return jsonLdSummary(JSON.parse($(node).text().slice(0, 40_000))); } catch { return []; }
  }).get().flat();
  const social = ["og:site_name", "og:title", "og:url", "twitter:site"].map(property => ({ property, content: $(`meta[property='${property}'],meta[name='${property}']`).attr("content")?.slice(0, 320) || null })).filter(item => item.content);
  const releaseSignals = {
    canonical: $("link[rel='canonical']").attr("href") || null,
    manifest: $("link[rel='manifest']").attr("href") || null,
    generator: $("meta[name='generator']").attr("content")?.slice(0, 240) || null,
    icons: $("link[rel*='icon']").length,
    versionedAssetSignals: $("script[src],link[href]").map((_, node) => $(node).attr("src") || $(node).attr("href") || "").get().filter(value => /[?&](v|ver|version|hash)=|\.[a-f0-9]{8,}\./i.test(value)).slice(0, 40),
  };
  const record = finding(
    "structured-web-provenance",
    "Web Intelligence",
    "Structured-web provenance and release signals",
    `Captured public structured-data, canonical, social-card, and release-descriptor signals from one bounded HTML response; ${jsonLd.length} JSON-LD summary object(s) were recognized.`,
    { url: base.toString(), status: response.status, jsonLd, social, releaseSignals, bytesRead: html.length, limitation: "Only the initial public HTML response was read. Structured data is publisher-supplied and is not independently verified." },
    "low",
    86,
    base.toString(),
  );
  record.entities = [{ type: "url", value: base.toString(), confidence: 96 }, ...jsonLd.filter(item => item.url).slice(0, 12).map(item => ({ type: "url" as const, value: String(item.url), confidence: 70 }))];
  return { findings: [record] };
}

export const MODULES: ModuleDefinition[] = [
  { id: "crt-subdomains", label: "Certificate Transparency", category: "Domain", appliesTo: ["domain", "url"], execute: crtSh },
  { id: "dns-posture", label: "DNS & Mail Posture", category: "Domain", appliesTo: ["domain", "url", "email"], execute: dnsRecords },
  { id: "email-disclosure", label: "Email & Disclosure Posture", category: "Domain", appliesTo: ["domain", "url", "email"], execute: emailDisclosureIntelligence },
  { id: "dns-crosscheck", label: "DNS-over-HTTPS Cross-check", category: "Domain", appliesTo: ["domain", "url", "email"], execute: dnsCrosscheck },
  { id: "rdap-whois", label: "RDAP / WHOIS", category: "Domain", appliesTo: ["domain", "url"], execute: rdapWhois },
  { id: "tls-certificate", label: "TLS Certificate", category: "Infrastructure", appliesTo: ["domain", "url"], execute: tlsCertificate },
  { id: "certificate-timeline", label: "Certificate Change Timeline", category: "Historical", appliesTo: ["domain", "url"], execute: certificateTimeline },
  { id: "http-fingerprint", label: "HTTP Fingerprint", category: "Infrastructure", appliesTo: ["domain", "url"], execute: httpFingerprint },
  { id: "ipinfo", label: "IPinfo Geo & ASN", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], requiresKey: "ipinfo", execute: passiveIpInfo },
  { id: "reverse-ptr", label: "Reverse DNS PTR", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], execute: ptrLookup },
  { id: "routed-prefix", label: "BGP Prefix & Owner", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], execute: routedPrefix },
  { id: "network-ownership-context", label: "Routing & RPKI Context", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], execute: networkOwnershipContext },
  { id: "abuseipdb", label: "AbuseIPDB", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], requiresKey: "abuseipdb", execute: abuseIpdb },
  { id: "shodan", label: "Shodan Passive Services", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], requiresKey: "shodan", execute: shodan },
  { id: "virustotal", label: "VirusTotal Reputation", category: "Threat Intelligence", appliesTo: ["domain", "url", "ip"], requiresKey: "virustotal", execute: virusTotal },
  { id: "urlscan", label: "urlscan.io History", category: "Web Intelligence", appliesTo: ["domain", "url"], requiresKey: "urlscan", execute: urlscan },
  { id: "wayback", label: "Wayback History", category: "Historical", appliesTo: ["domain", "url"], execute: wayback },
  { id: "historical-web-change", label: "Public Web Change Timeline", category: "Historical", appliesTo: ["domain", "url"], execute: historicalWebChange },
  { id: "common-crawl", label: "Common Crawl Index", category: "Historical", appliesTo: ["domain", "url"], execute: commonCrawl },
  { id: "public-search", label: "Free Public Search", category: "Research", appliesTo: ["domain", "url", "company"], execute: publicSearchDiscovery },
  { id: "public-web-crawl", label: "Robots-aware Web Crawl", category: "Web Intelligence", appliesTo: ["domain", "url"], execute: robotsAwareCrawl },
  { id: "public-policy-surface", label: "Public Policy & Release Signals", category: "Web Intelligence", appliesTo: ["domain", "url"], execute: publicPolicySurface },
  { id: "structured-web-provenance", label: "Structured-Web Provenance", category: "Web Intelligence", appliesTo: ["domain", "url"], execute: structuredWebProvenance },
  { id: "research-dorks", label: "Research Query Builder", category: "Research", appliesTo: ["domain", "url", "company"], execute: dorkBuilder },
  { id: "public-web-surface", label: "Public Web Surface", category: "Web Intelligence", appliesTo: ["domain", "url"], execute: publicWebSurface },
  { id: "document-metadata", label: "Document HTTP Metadata", category: "Document Intelligence", appliesTo: ["url"], execute: documentMetadata },
  { id: "exposure-research", label: "Exposure Research Pivots", category: "Research", appliesTo: ["domain", "url"], execute: exposureResearch },
  { id: "public-advisory-pivots", label: "Public Advisory Pivots", category: "Threat Intelligence", appliesTo: ["domain", "url", "company"], execute: publicAdvisoryPivots },
  { id: "defensive-brand-leads", label: "Defensive Brand Leads", category: "Brand Intelligence", appliesTo: ["domain", "url", "company"], execute: defensiveBrandLeads },
  { id: "username-matrix", label: "Username Matrix", category: "Identity", appliesTo: ["username"], execute: usernameProfiles },
  { id: "username-presence", label: "Bounded Username Presence", category: "Identity", appliesTo: ["username"], execute: publicUsernamePresence },
  { id: "public-social-profile-links", label: "Public Social Profile Links", category: "Social Intelligence", appliesTo: ["username"], execute: publicSocialProfileLinks },
  { id: "github-supply-chain", label: "GitHub Supply Chain", category: "Supply Chain", appliesTo: ["username"], execute: githubSupplyChain },
  { id: "email-context", label: "Email Posture", category: "Identity", appliesTo: ["email"], execute: emailPosture },
  { id: "email-ownership-posture", label: "Consent-bound Email Posture", category: "Identity", appliesTo: ["email"], execute: consentBoundEmailPosture },
  { id: "onion-index-leads", label: "Onion-index Research Lead", category: "Threat Intelligence", appliesTo: ["domain", "url", "company", "email"], execute: onionIndexLeads },
  { id: "community-integration-status", label: "Community Integration Status", category: "Community Intelligence", appliesTo: ["domain", "company", "username"], execute: communityIntegrationStatus },
  { id: "corporate-research", label: "Corporate Pivots", category: "Corporate", appliesTo: ["company"], execute: corporateLinks },
  { id: "phone-research", label: "Phone Research Pivots", category: "Identity", appliesTo: ["phone"], execute: phoneResearch },
  { id: "asn-research", label: "ASN Research Pivots", category: "IP Intelligence", appliesTo: ["asn"], execute: asnResearch },
];

export function modulesFor(target: ReconTarget, options: ReconOptions) {
  const selectedModules = options.enabledModules && options.enabledModules.length > 0 ? options.enabledModules : undefined;
  return MODULES.filter(module => module.appliesTo.includes(target.type)).filter(module => !selectedModules || selectedModules.includes(module.id));
}
