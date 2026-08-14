import { resolve4, resolve6, resolveMx, resolveNs, resolveTxt, resolveCname, resolvePtr } from "node:dns/promises";
import tls from "node:tls";
import { ENV } from "../_core/env";
import type { ModuleDefinition, ModuleResult, ReconFinding, ReconOptions, ReconTarget, RiskLevel } from "./types";

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
const rootDomain = (hostname: string) => hostname.split(".").slice(-2).join(".");
const query = (q: string) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;

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

export const MODULES: ModuleDefinition[] = [
  { id: "crt-subdomains", label: "Certificate Transparency", category: "Domain", appliesTo: ["domain", "url"], execute: crtSh },
  { id: "dns-posture", label: "DNS & Mail Posture", category: "Domain", appliesTo: ["domain", "url", "email"], execute: dnsRecords },
  { id: "dns-crosscheck", label: "DNS-over-HTTPS Cross-check", category: "Domain", appliesTo: ["domain", "url", "email"], execute: dnsCrosscheck },
  { id: "rdap-whois", label: "RDAP / WHOIS", category: "Domain", appliesTo: ["domain", "url"], execute: rdapWhois },
  { id: "tls-certificate", label: "TLS Certificate", category: "Infrastructure", appliesTo: ["domain", "url"], execute: tlsCertificate },
  { id: "http-fingerprint", label: "HTTP Fingerprint", category: "Infrastructure", appliesTo: ["domain", "url"], execute: httpFingerprint },
  { id: "ipinfo", label: "IPinfo Geo & ASN", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], requiresKey: "ipinfo", execute: passiveIpInfo },
  { id: "reverse-ptr", label: "Reverse DNS PTR", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], execute: ptrLookup },
  { id: "routed-prefix", label: "BGP Prefix & Owner", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], execute: routedPrefix },
  { id: "abuseipdb", label: "AbuseIPDB", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], requiresKey: "abuseipdb", execute: abuseIpdb },
  { id: "shodan", label: "Shodan Passive Services", category: "IP Intelligence", appliesTo: ["domain", "url", "ip"], requiresKey: "shodan", execute: shodan },
  { id: "virustotal", label: "VirusTotal Reputation", category: "Threat Intelligence", appliesTo: ["domain", "url", "ip"], requiresKey: "virustotal", execute: virusTotal },
  { id: "urlscan", label: "urlscan.io History", category: "Web Intelligence", appliesTo: ["domain", "url"], requiresKey: "urlscan", execute: urlscan },
  { id: "wayback", label: "Wayback History", category: "Historical", appliesTo: ["domain", "url"], execute: wayback },
  { id: "common-crawl", label: "Common Crawl Index", category: "Historical", appliesTo: ["domain", "url"], execute: commonCrawl },
  { id: "research-dorks", label: "Research Query Builder", category: "Research", appliesTo: ["domain", "url", "company"], execute: dorkBuilder },
  { id: "public-web-surface", label: "Public Web Surface", category: "Web Intelligence", appliesTo: ["domain", "url"], execute: publicWebSurface },
  { id: "document-metadata", label: "Document HTTP Metadata", category: "Document Intelligence", appliesTo: ["url"], execute: documentMetadata },
  { id: "exposure-research", label: "Exposure Research Pivots", category: "Research", appliesTo: ["domain", "url"], execute: exposureResearch },
  { id: "username-matrix", label: "Username Matrix", category: "Identity", appliesTo: ["username"], execute: usernameProfiles },
  { id: "email-context", label: "Email Posture", category: "Identity", appliesTo: ["email"], execute: emailPosture },
  { id: "corporate-research", label: "Corporate Pivots", category: "Corporate", appliesTo: ["company"], execute: corporateLinks },
  { id: "phone-research", label: "Phone Research Pivots", category: "Identity", appliesTo: ["phone"], execute: phoneResearch },
  { id: "asn-research", label: "ASN Research Pivots", category: "IP Intelligence", appliesTo: ["asn"], execute: asnResearch },
];

export function modulesFor(target: ReconTarget, options: ReconOptions) {
  const selectedModules = options.enabledModules && options.enabledModules.length > 0 ? options.enabledModules : undefined;
  return MODULES.filter(module => module.appliesTo.includes(target.type)).filter(module => !selectedModules || selectedModules.includes(module.id));
}
