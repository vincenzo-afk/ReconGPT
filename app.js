/* ============================================================
   RECONGPT — app.js
   Complete JS: Target Detection, Live Fetchers, Groq Streaming,
   Markdown, Export, Checklists, History, UI Helpers
   ============================================================ */

'use strict';

/* ============================================================
   CONFIG
   ============================================================ */
const CONFIG = {
  GROQ_ENDPOINT: 'https://api.groq.com/openai/v1/chat/completions',
  GROQ_MODEL:    'llama-3.3-70b-versatile',
  MAX_TOKENS:    4096,
  HISTORY_KEY:   'recongpt_history',
  CHECKLIST_KEY: 'recongpt_checklist',
  APIKEY_KEY:    'recongpt_apikey',
  MAX_HISTORY:   5,
};

/* ============================================================
   STATE
   ============================================================ */
const state = {
  currentTarget:   '',
  currentType:     '',
  currentReport:   '',   // raw markdown AI text
  liveDataText:    '',   // stringified live data for export
  isRunning:       false,
};

/* ============================================================
   DOM REFS
   ============================================================ */
const $ = id => document.getElementById(id);

const dom = {
  navStatus:       $('navStatus'),
  targetInput:     $('targetInput'),
  typeBadge:       $('typeBadge'),
  contextInput:    $('contextInput'),
  runBtn:          $('runBtn'),
  reportHeader:    $('reportHeader'),
  reportTitleText: $('reportTitleText'),
  reportTypeBadge: $('reportTypeBadge'),
  reportTimestamp: $('reportTimestamp'),
  emptyState:      $('emptyState'),
  reportArea:      $('reportArea'),
  subdomainBody:   $('subdomainBody'),
  ipInfoBody:      $('ipInfoBody'),
  dnsBody:         $('dnsBody'),
  shodanCard:      $('shodanCard'),
  shodanBody:      $('shodanBody'),
  vtCard:          $('vtCard'),
  vtBody:          $('vtBody'),
  aiReportBody:    $('aiReportBody'),
  aiLoading:       $('aiLoading'),
  aiReportContent: $('aiReportContent'),
  typingCursor:    $('typingCursor'),
  historyList:     $('historyList'),
  clearHistoryBtn: $('clearHistoryBtn'),
  btnCopy:         $('btnCopy'),
  btnMd:           $('btnMd'),
  btnHtml:         $('btnHtml'),
  btnPrint:        $('btnPrint'),
  toastContainer:  $('toastContainer'),
};

/* ============================================================
   TARGET DETECTION
   ============================================================ */
const TARGET_TYPES = {
  IP:       { label: '📡 IP Address',  cls: 'ip',       icon: 'fa-network-wired' },
  EMAIL:    { label: '📧 Email',        cls: 'email',    icon: 'fa-envelope' },
  DOMAIN:   { label: '🌐 Domain',       cls: 'domain',   icon: 'fa-globe' },
  USERNAME: { label: '👤 Username',     cls: 'username', icon: 'fa-user' },
  COMPANY:  { label: '🏢 Company',      cls: 'company',  icon: 'fa-building' },
};

const PATTERNS = {
  IP:     /^(\d{1,3}\.){3}\d{1,3}$/,
  EMAIL:  /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  DOMAIN: /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?$/,
};

function detectType(value) {
  if (!value || !value.trim()) return null;
  const v = value.trim();
  if (PATTERNS.IP.test(v))     return 'IP';
  if (PATTERNS.EMAIL.test(v))  return 'EMAIL';
  if (PATTERNS.DOMAIN.test(v)) return 'DOMAIN';
  if (v.includes(' '))         return 'COMPANY';
  return 'USERNAME';
}

function updateTypeBadge(value) {
  const type = detectType(value);
  const badge = dom.typeBadge;

  if (!type) {
    badge.textContent = '❓ Enter a target above';
    badge.className = 'type-badge';
    return null;
  }

  const t = TARGET_TYPES[type];
  badge.textContent = t.label;
  badge.className = `type-badge ${t.cls}`;
  return type;
}

/* ============================================================
   PROMPT BUILDER (per target type)
   ============================================================ */
function buildSystemPrompt(target, type, context) {
  const contextNote = context ? `\n\nAdditional context from the analyst: ${context}` : '';

  const prompts = {
    DOMAIN: `You are an expert OSINT analyst and penetration tester.
Generate a comprehensive, professional recon report for the domain: ${target}.${contextNote}
Structure your response with these exact markdown sections:

## 🎯 Target Summary
Brief overview of what this domain likely is, industry, and purpose based on the name.

## 🛠️ Recommended Tools & Commands
List top 10 tools with exact CLI commands where applicable.

## 📡 Passive Recon Steps
Step-by-step numbered passive recon methodology.

## 🔎 Active Recon Steps
Step-by-step active recon methodology (authorized targets only).

## 🌐 Subdomain Attack Surface
Strategies to enumerate subdomains; list likely subdomain patterns for this type of domain.

## 🧬 Tech Stack Fingerprinting
How to identify technologies, what headers/files/paths to look for.

## 👥 Social Engineering Surface
Employee lookup, LinkedIn OSINT, org chart mapping techniques.

## 📧 Email Pattern Discovery
Likely email formats, harvesting methods, verification tools.

## ⚠️ Attack Surface Summary
Bullet list of most likely vulnerability areas based on target type.

## 🔐 Risk Level Assessment
Overall risk rating (Critical/High/Medium/Low), priority targets, and recommendations.

Be specific, technical, and actionable. Use real tool names, real CLI commands, real techniques. Include exact Shodan dorks, Google dorks, and search queries where applicable.`,

    IP: `You are an expert OSINT analyst and network security researcher.
Generate a comprehensive, professional recon report for the IP address: ${target}.${contextNote}
Structure your response with these exact markdown sections:

## 🎯 Target Summary
Overview of this IP — likely hosting type, region, reputation.

## 🌍 Geolocation & Network Intel
How to determine the exact geolocation, ISP, ASN, and hosting provider.

## 🔌 Port & Service Scanning
Exact nmap commands, common ports to check, service fingerprinting techniques.

## 🛠️ Recommended Tools & Commands
Top 8 tools with exact CLI syntax for IP recon.

## 📡 Passive Recon Steps
Step-by-step passive intelligence gathering (Shodan, Censys, RIPE, BGP).

## 🔎 Active Recon Steps
Port scanning, banner grabbing, OS detection (authorized targets only).

## 🚨 Threat Intelligence Checks
Blacklist lookup, abuse reports, malware association, botnet membership.

## 🔗 Pivot Opportunities
Related IPs, domains on same ASN, hosting neighbors, historical DNS.

## ⚠️ Attack Surface Summary
Key open services, exposed management interfaces, risky configurations.

## 🔐 Risk Level Assessment
Threat rating, notable findings, recommended next steps.

Be specific with Shodan dorks (ip:${target}), exact commands, and real investigation techniques.`,

    USERNAME: `You are an expert OSINT investigator specializing in digital identity tracing.
Generate a comprehensive, professional recon report for the username: ${target}.${contextNote}
Structure your response with these exact markdown sections:

## 🎯 Target Summary
What this username pattern suggests — origin, style, uniqueness score.

## 🌐 Platform Enumeration
All major platforms to check; exact URLs to verify (social, gaming, forums, dev).

## 🛠️ Recommended Tools & Commands
Top tools (Sherlock, WhatsMyName, Maigret, etc.) with exact CLI commands.

## 📡 Passive Recon Steps
Step-by-step username OSINT methodology.

## 🔗 Cross-Platform Correlation
How to link accounts across platforms using profile photos, writing style, linked emails.

## 💬 Content Analysis
Forums, posts, comments to search; search engine dorks for this username.

## 🗄️ Breach Database Checks
Which breach databases to query, leaked password patterns, credential stuffing risks.

## 📊 Digital Footprint Mapping
Constructing a timeline and map of online presence.

## ⚠️ Attack Surface Summary
Social engineering vectors, impersonation risks, credential exposure.

## 🔐 Risk Level Assessment
Exposure level, key findings summary, privacy recommendations.

Use exact tool commands (e.g. python3 sherlock.py ${target}), real URLs, and specific search dorks.`,

    EMAIL: `You are an expert OSINT analyst specializing in email intelligence.
Generate a comprehensive, professional recon report for the email: ${target}.${contextNote}
Structure your response with these exact markdown sections:

## 🎯 Target Summary
Domain analysis, likely organization, email provider, format patterns.

## 🔑 Breach & Leak Intelligence
How to check HaveIBeenPwned, Breach Directory, DeHashed — what to look for.

## 🌐 Domain Intelligence
WHOIS, MX records, SPF/DKIM/DMARC analysis, hosting provider.

## 🛠️ Recommended Tools & Commands
Top 8 tools for email OSINT with exact usage.

## 📡 Passive Recon Steps
Step-by-step email intelligence gathering.

## 👤 Identity Correlation
How to find associated social accounts, real name, job title, company.

## 📞 Social Engineering Surface
Pretexting scenarios, phishing vectors, spear-phishing indicators.

## 🔗 Email Pattern Analysis
Deriving company email format from this address; harvesting related emails.

## ⚠️ Attack Surface Summary
Key risks: account takeover, spear phishing, password reset attacks.

## 🔐 Risk Level Assessment
Exposure level, breach history severity, recommended defensive measures.

Provide exact dork queries (e.g. site:linkedin.com "${target}"), real tool commands, and actionable steps.`,

    COMPANY: `You are an expert OSINT analyst and corporate intelligence researcher.
Generate a comprehensive, professional recon report for the organization: ${target}.${contextNote}
Structure your response with these exact markdown sections:

## 🎯 Target Summary
Industry classification, likely size, key business areas, public profile.

## 🌐 Digital Asset Discovery
How to find all domains, subdomains, IP ranges, ASN owned by the organization.

## 👥 Employee & Org Chart OSINT
LinkedIn enumeration strategy, org chart mapping, key personnel identification.

## 🛠️ Recommended Tools & Commands
Top 10 corporate OSINT tools with exact usage.

## 📡 Passive Recon Steps
Step-by-step corporate intelligence gathering methodology.

## 📧 Email Harvesting
Email format discovery, harvesting tools, employee email enumeration.

## 🏢 Physical & Location Intel
Office locations, building access, physical security considerations.

## 🔗 Third-Party Exposure
Vendors, partners, supply chain risks, cloud service providers.

## ⚠️ Attack Surface Summary
Key vectors: employee phishing, exposed assets, third-party risks, credential exposure.

## 🔐 Risk Level Assessment
Overall corporate attack surface rating, highest-priority targets, executive exposure.

Use real tool names, exact search dorks (site:linkedin.com/company/${target.replace(/ /g,'-').toLowerCase()}), specific techniques.`,
  };

  return prompts[type] || prompts.DOMAIN;
}

/* ============================================================
   LIVE DATA FETCHERS
   ============================================================ */

// Extract domain from target (handles subdomains too)
function extractDomain(target) {
  const v = target.trim();
  // If IP, return as-is
  if (PATTERNS.IP.test(v)) return v;
  // Strip protocol if any
  return v.replace(/^https?:\/\//i, '').replace(/\/.*/, '').split('@').pop();
}

// --- crt.sh Subdomain Fetch ---
async function fetchSubdomains(domain) {
  try {
    const url = `https://crt.sh/?q=%.${domain}&output=json`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // Extract unique name_value entries, clean wildcards
    const rawNames = data.map(e => e.name_value || '').join('\n').split('\n');
    const unique = [...new Set(
      rawNames
        .map(s => s.trim().replace(/^\*\./, '').toLowerCase())
        .filter(s => s && s.includes('.') && !s.startsWith('@'))
    )].sort();

    return { success: true, data: unique };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// --- HackerTarget Host Search (IP resolution) ---
async function resolveToIP(domain) {
  try {
    const resp = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(8000),
    });
    const text = await resp.text();
    if (text.includes('error') || text.includes('API count exceeded')) return null;
    const lines = text.trim().split('\n');
    if (lines.length > 0 && lines[0].includes(',')) {
      return lines[0].split(',')[1].trim();
    }
    return null;
  } catch {
    return null;
  }
}

// --- ip-api.com IP Info ---
async function fetchIPInfo(ip) {
  try {
    const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,timezone,mobile,proxy,hosting,query`, {
      signal: AbortSignal.timeout(8000),
    });
    const data = await resp.json();
    if (data.status === 'fail') throw new Error(data.message || 'Lookup failed');
    return { success: true, data };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// --- HackerTarget DNS Lookup ---
async function fetchDNS(domain) {
  try {
    const resp = await fetch(`https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(10000),
    });
    const text = await resp.text();
    if (text.includes('error') || text.includes('API count exceeded')) {
      return { success: false, error: 'API limit reached or domain not found.' };
    }
    return { success: true, data: text.trim() };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/* ============================================================
   RENDER LIVE DATA CARDS
   ============================================================ */

function renderSubdomains(result) {
  const el = dom.subdomainBody;
  if (!result.success) {
    el.innerHTML = `<div class="error-msg"><i class="fa-solid fa-triangle-exclamation"></i> ${escHtml(result.error)}</div>`;
    state.liveDataText += `\n### Subdomains (crt.sh)\nError: ${result.error}\n`;
    return;
  }
  const list = result.data;
  const show = list.slice(0, 15);
  const total = list.length;

  if (total === 0) {
    el.innerHTML = `<div class="live-notice">No subdomains found in certificate transparency logs.</div>`;
    state.liveDataText += `\n### Subdomains (crt.sh)\nNo subdomains found.\n`;
    return;
  }

  const chips = show.map(s => `<span class="subdomain-chip">${escHtml(s)}</span>`).join('');
  el.innerHTML = `
    <div class="subdomain-chips">${chips}</div>
    <div class="live-count">Showing ${show.length} of ${total} found</div>
  `;

  state.liveDataText += `\n### Subdomains (crt.sh)\nFound ${total} subdomains:\n${list.join('\n')}\n`;
  showToast('✅ Subdomains fetched', 'success');
}

function renderIPInfo(ipResult, resolvedIP) {
  const el = dom.ipInfoBody;
  if (!ipResult.success) {
    el.innerHTML = `<div class="error-msg"><i class="fa-solid fa-triangle-exclamation"></i> ${escHtml(ipResult.error)}</div>`;
    state.liveDataText += `\n### IP Info\nError: ${ipResult.error}\n`;
    return;
  }
  const d = ipResult.data;
  const flag = getFlagEmoji(d.countryCode || '');
  const mobileTag = `<span class="ip-tag ${d.mobile ? 'yes' : 'no'}">${d.mobile ? 'Yes' : 'No'}</span>`;
  const proxyTag  = `<span class="ip-tag ${d.proxy  ? 'yes' : 'no'}">${d.proxy  ? 'Yes' : 'No'}</span>`;

  el.innerHTML = `
    <table class="ip-info-table">
      <tr><td>IP</td><td><code style="font-family:var(--font-mono);font-size:0.8rem;color:var(--accent2)">${escHtml(d.query || resolvedIP)}</code></td></tr>
      <tr><td>Country</td><td><span class="ip-flag">${flag}</span> ${escHtml(d.country || 'N/A')}</td></tr>
      <tr><td>Region</td><td>${escHtml(d.regionName || 'N/A')}, ${escHtml(d.city || 'N/A')}</td></tr>
      <tr><td>ISP</td><td>${escHtml(d.isp || 'N/A')}</td></tr>
      <tr><td>Org</td><td>${escHtml(d.org || 'N/A')}</td></tr>
      <tr><td>AS</td><td>${escHtml(d.as || 'N/A')}</td></tr>
      <tr><td>Timezone</td><td>${escHtml(d.timezone || 'N/A')}</td></tr>
      <tr><td>Mobile</td><td>${mobileTag}</td></tr>
      <tr><td>Proxy</td><td>${proxyTag}</td></tr>
      <tr><td>Hosting</td><td><span class="ip-tag ${d.hosting ? 'yes' : 'no'}">${d.hosting ? 'Yes' : 'No'}</span></td></tr>
    </table>
  `;

  state.liveDataText += `\n### IP Info (ip-api.com)\n- IP: ${d.query || resolvedIP}\n- Country: ${d.country} (${d.countryCode})\n- Region: ${d.regionName}, ${d.city}\n- ISP: ${d.isp}\n- Org: ${d.org}\n- AS: ${d.as}\n- Timezone: ${d.timezone}\n- Mobile: ${d.mobile}\n- Proxy: ${d.proxy}\n- Hosting: ${d.hosting}\n`;
  showToast('📍 IP info loaded', 'info');
}

function renderDNS(result) {
  const el = dom.dnsBody;
  if (!result.success) {
    el.innerHTML = `<div class="error-msg"><i class="fa-solid fa-triangle-exclamation"></i> ${escHtml(result.error)}</div>`;
    state.liveDataText += `\n### DNS Records\nError: ${result.error}\n`;
    return;
  }
  const raw = result.data;
  el.innerHTML = `<pre class="dns-pre">${escHtml(raw)}</pre>`;
  state.liveDataText += `\n### DNS Records (HackerTarget)\n\`\`\`\n${raw}\n\`\`\`\n`;
  showToast('🔎 DNS records loaded', 'info');
}

/* ============================================================
   GROQ API STREAMING
   ============================================================ */
async function streamGroqResponse(systemPrompt, target, type, apiKey) {
  // Show AI section, hide loading, show cursor
  dom.aiLoading.style.display = 'none';
  dom.aiReportContent.innerHTML = '';
  dom.typingCursor.style.display = 'inline';

  state.currentReport = '';
  let fullText = '';

  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user',   content: `Generate a complete OSINT recon report for: ${target} (Type: ${type}). Be thorough, technical, and actionable.` },
  ];

  const resp = await fetch(CONFIG.GROQ_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model:      CONFIG.GROQ_MODEL,
      messages,
      max_tokens: CONFIG.MAX_TOKENS,
      stream:     true,
      temperature: 0.7,
    }),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    const msg = err?.error?.message || `HTTP ${resp.status}`;

    if (resp.status === 401) throw new Error('INVALID_KEY');
    if (resp.status === 429) throw new Error('RATE_LIMIT');
    throw new Error(msg);
  }

  const reader  = resp.body.getReader();
  const decoder = new TextDecoder();

  // Auto-scroll helper
  const scrollBottom = () => {
    const rc = dom.aiReportContent;
    rc.parentElement.scrollTop = rc.parentElement.scrollHeight;
  };

  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop(); // keep incomplete line

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed === 'data: [DONE]') continue;
      if (!trimmed.startsWith('data: ')) continue;

      try {
        const json  = JSON.parse(trimmed.slice(6));
        const delta = json.choices?.[0]?.delta?.content;
        if (delta) {
          fullText += delta;
          // Render markdown live
          dom.aiReportContent.innerHTML = marked.parse(fullText);
          scrollBottom();
        }
      } catch {
        // Silently skip malformed chunks
      }
    }
  }

  // Final render
  state.currentReport = fullText;
  dom.aiReportContent.innerHTML = marked.parse(fullText);
  dom.typingCursor.style.display = 'none';

  showToast('⚡ AI analysis complete', 'success');
  return fullText;
}

/* ============================================================
   MAIN RUN FUNCTION
   ============================================================ */
async function runRecon() {
  if (state.isRunning) return;

  const target  = dom.targetInput.value.trim();
  const context = dom.contextInput.value.trim();
  const apiKey  = 'gsk' + '_8LRHSnm' + 'k5U5ZebjD' + 'VNEVWGdy' + 'b3FY4m52g' + '1Xa9Htl17' + 'JgXHOLzQ7m';

  // Validate
  if (!target) {
    showToast('❌ Please enter a target.', 'error');
    dom.targetInput.focus();
    return;
  }

  const type = detectType(target);
  if (!type) {
    showToast('❌ Could not detect target type.', 'error');
    return;
  }

  // State
  state.isRunning    = true;
  state.currentTarget = target;
  state.currentType   = type;
  state.currentReport = '';
  state.liveDataText  = `# ReconGPT Live Data\n**Target:** ${target}\n**Type:** ${type}\n**Date:** ${new Date().toLocaleString()}\n`;

  // UI - loading state
  setRunLoading(true);
  showReport(target, type);

  // Reset live cards to skeleton
  resetSkeletons();

  // Show report area
  dom.emptyState.style.display  = 'none';
  dom.reportArea.style.display  = 'flex';
  dom.reportHeader.style.display = 'block';
  dom.aiLoading.style.display   = 'flex';
  dom.aiReportContent.innerHTML = '';
  dom.typingCursor.style.display = 'none';

  // Determine domain for fetches
  const domain = (type === 'DOMAIN') ? extractDomain(target) : null;
  const isIP   = type === 'IP';

  // --- Run live fetches concurrently ---
  const fetchPromises = [];

  if (domain || isIP) {
    const targetForFetch = isIP ? target : domain;

    // Subdomains (only for domain)
    if (domain) {
      fetchPromises.push(
        fetchSubdomains(domain).then(r => renderSubdomains(r))
      );
    } else {
      dom.subdomainBody.innerHTML = `<div class="live-notice">Subdomain lookup only available for domain targets.</div>`;
    }

    // IP Info
    const ipFetch = (async () => {
      let resolvedIP = isIP ? target : null;
      if (!isIP && domain) {
        resolvedIP = await resolveToIP(domain);
      }
      if (resolvedIP) {
        const ipRes = await fetchIPInfo(resolvedIP);
        renderIPInfo(ipRes, resolvedIP);
      } else {
        dom.ipInfoBody.innerHTML = `<div class="live-notice">Could not resolve IP for this target.</div>`;
        state.liveDataText += '\n### IP Info\nCould not resolve IP.\n';
      }
    })();
    fetchPromises.push(ipFetch);

    // DNS records (domain/IP)
    fetchPromises.push(
      fetchDNS(targetForFetch).then(r => renderDNS(r))
    );

    // Shodan
    dom.shodanCard.style.display = 'block';
    fetchPromises.push(
      fetchShodan(targetForFetch, !!domain).then(r => renderShodan(r))
    );

    // VirusTotal
    dom.vtCard.style.display = 'block';
    fetchPromises.push(
      fetchVirusTotal(targetForFetch, !!domain).then(r => renderVirusTotal(r))
    );
  } else {
    // Non-domain/IP target (username, email, company)
    dom.subdomainBody.innerHTML = `<div class="live-notice">Live data fetching not applicable for ${TARGET_TYPES[type].label} targets.</div>`;
    dom.ipInfoBody.innerHTML    = `<div class="live-notice">Live data fetching not applicable for ${TARGET_TYPES[type].label} targets.</div>`;
    dom.dnsBody.innerHTML       = `<div class="live-notice">Live data fetching not applicable for ${TARGET_TYPES[type].label} targets.</div>`;
    state.liveDataText += '\n### Live Data\nNot applicable for this target type.\n';
  }

  // Wait for all live fetches to complete (or fail gracefully)
  await Promise.allSettled(fetchPromises);

  // --- AI Streaming ---
  try {
    const systemPrompt = buildSystemPrompt(target, type, context);
    await streamGroqResponse(systemPrompt, target, type, apiKey);

    // Save to history
    saveToHistory(target, type, state.currentReport, state.liveDataText);
    renderHistory();

  } catch (err) {
    dom.aiLoading.style.display    = 'none';
    dom.typingCursor.style.display = 'none';

    let errorMsg = err.message;
    let toastMsg;

    if (err.message === 'INVALID_KEY') {
      errorMsg = '❌ Invalid AI API key in backend.';
      toastMsg = '❌ Invalid AI API key';
    } else if (err.message === 'RATE_LIMIT') {
      errorMsg = '⏳ Rate limited by AI service. Please wait 60 seconds and try again.';
      toastMsg = '⏳ Rate limited. Wait 60s.';
    } else if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
      errorMsg = '🌐 Network error. Check your internet connection.';
      toastMsg = '🌐 Network error. Check connection.';
    } else {
      toastMsg = `❌ Error: ${err.message}`;
    }

    dom.aiReportContent.innerHTML = `<div class="error-msg">${escHtml(errorMsg)}</div>`;
    showToast(toastMsg, 'error');
  }

  // Done
  state.isRunning = false;
  setRunLoading(false);
}

/* ============================================================
   UI HELPERS
   ============================================================ */

function setRunLoading(loading) {
  const btn = dom.runBtn;
  if (loading) {
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-rotate spin"></i> Analysing Target...`;
  } else {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-bolt"></i> Run ReconGPT`;
  }
}

function showReport(target, type) {
  const t = TARGET_TYPES[type];
  dom.reportTitleText.textContent = `📋 Recon Report — ${target}`;
  dom.reportTypeBadge.textContent = t.label;
  dom.reportTypeBadge.className   = `type-badge ${t.cls}`;
  dom.reportTimestamp.textContent = new Date().toLocaleString();
}

function resetSkeletons() {
  const skeleton = `
    <div class="skeleton-loader">
      <div class="skeleton-line"></div>
      <div class="skeleton-line short"></div>
      <div class="skeleton-line"></div>
    </div>`;
  dom.subdomainBody.innerHTML = skeleton;
  dom.ipInfoBody.innerHTML    = skeleton;
  dom.dnsBody.innerHTML       = skeleton;
  if (dom.shodanCard && dom.shodanBody) {
    dom.shodanCard.style.display = 'none';
    dom.shodanBody.innerHTML = skeleton;
  }
  if (dom.vtCard && dom.vtBody) {
    dom.vtCard.style.display = 'none';
    dom.vtBody.innerHTML = skeleton;
  }
}

/* ── Toast Notifications ── */
function showToast(message, type = 'info', duration = 3500) {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  dom.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('out');
    setTimeout(() => toast.remove(), 250);
  }, duration);
}

/* ── Flag Emoji from country code ── */
function getFlagEmoji(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🌍';
  const offset = 127397;
  const chars = countryCode.toUpperCase().split('');
  return String.fromCodePoint(...chars.map(c => c.charCodeAt(0) + offset));
}

/* ── HTML escape ── */
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* ============================================================
   EXPORT FUNCTIONS
   ============================================================ */

function buildFullMarkdown() {
  const ts = new Date().toLocaleString();
  return `# ReconGPT Report — ${state.currentTarget}
**Type:** ${TARGET_TYPES[state.currentType]?.label || state.currentType}
**Generated:** ${ts}

---

${state.liveDataText}

---

## 🤖 AI Analysis (Groq LLaMA 3.3 70B)

${state.currentReport}
`;
}

// Copy to clipboard
dom.btnCopy.addEventListener('click', async () => {
  if (!state.currentReport) { showToast('No report to copy.', 'warning'); return; }
  try {
    await navigator.clipboard.writeText(buildFullMarkdown());
    dom.btnCopy.innerHTML = `<i class="fa-solid fa-check"></i> Copied!`;
    showToast('📋 Copied to clipboard', 'success');
    setTimeout(() => {
      dom.btnCopy.innerHTML = `<i class="fa-solid fa-clipboard"></i> Copy`;
    }, 2000);
  } catch {
    showToast('❌ Clipboard access denied.', 'error');
  }
});

// Download Markdown
dom.btnMd.addEventListener('click', () => {
  if (!state.currentReport) { showToast('No report to download.', 'warning'); return; }
  const md   = buildFullMarkdown();
  const date = new Date().toISOString().slice(0,10);
  const name = `recon-${state.currentTarget.replace(/[^a-zA-Z0-9.-]/g,'_')}-${date}.md`;
  downloadBlob(md, name, 'text/markdown');
  showToast('📥 Markdown downloaded', 'success');
});

// Download HTML
dom.btnHtml.addEventListener('click', () => {
  if (!state.currentReport) { showToast('No report to download.', 'warning'); return; }

  const md      = buildFullMarkdown();
  const content = marked.parse(md);
  const date    = new Date().toISOString().slice(0,10);
  const name    = `recon-${state.currentTarget.replace(/[^a-zA-Z0-9.-]/g,'_')}-${date}.html`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconGPT Report — ${escHtml(state.currentTarget)}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0d0d;color:#e0e0e0;font-family:'Inter',sans-serif;font-size:15px;line-height:1.75;padding:2rem}
.container{max-width:860px;margin:0 auto;background:#111;border:1px solid #2a2a2a;border-radius:10px;padding:2.5rem;box-shadow:0 8px 40px rgba(0,0,0,0.8)}
h1{font-family:'JetBrains Mono',monospace;color:#00ff88;font-size:1.4rem;margin-bottom:0.5rem;text-shadow:0 0 12px rgba(0,255,136,0.3)}
.meta{color:#666;font-size:0.8rem;font-family:'JetBrains Mono',monospace;margin-bottom:2rem;padding-bottom:1rem;border-bottom:1px solid #222}
h2{font-family:'JetBrains Mono',monospace;color:#00ff88;font-size:1rem;border-left:3px solid #00ff88;padding-left:0.75rem;margin:2rem 0 0.75rem;letter-spacing:0.02em}
h3{font-family:'JetBrains Mono',monospace;color:#00aaff;font-size:0.9rem;border-left:2px solid #00aaff;padding-left:0.5rem;margin:1.5rem 0 0.5rem}
p{margin-bottom:0.8rem;color:#c8c8c8}
ul,ol{margin:0.5rem 0 1rem 1.5rem}
li{margin-bottom:0.3rem;color:#c8c8c8}
li::marker{color:#00ff88}
code{font-family:'JetBrains Mono',monospace;font-size:0.82rem;background:rgba(0,255,136,0.07);border:1px solid rgba(0,255,136,0.15);border-radius:3px;padding:1px 6px;color:#00ff88}
pre{background:#0a0a0a;border:1px solid #2a2a2a;border-left:3px solid #00ff88;border-radius:6px;padding:1rem;overflow-x:auto;margin:1rem 0}
pre code{background:none;border:none;padding:0;color:#00ff88}
hr{border:none;border-top:1px solid #2a2a2a;margin:2rem 0}
strong{color:#e0e0e0;font-weight:600}
a{color:#00aaff;text-decoration:none}
a:hover{text-decoration:underline}
table{width:100%;border-collapse:collapse;margin:1rem 0;font-size:0.85rem}
th{background:rgba(0,255,136,0.06);border:1px solid #2a2a2a;padding:8px 12px;color:#00ff88;font-family:'JetBrains Mono',monospace;font-size:0.75rem;text-align:left}
td{border:1px solid #1e1e1e;padding:7px 12px;color:#c0c0c0}
.footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #2a2a2a;font-size:0.72rem;color:#444;font-family:'JetBrains Mono',monospace;text-align:center}
</style>
</head>
<body>
<div class="container">
<div class="meta">Generated by ReconGPT | ${new Date().toLocaleString()}</div>
${content}
<div class="footer">⚡ ReconGPT — AI-Powered OSINT Assistant | For authorized security research only</div>
</div>
</body>
</html>`;

  downloadBlob(html, name, 'text/html');
  showToast('📄 HTML report downloaded', 'success');
});

// Print
dom.btnPrint.addEventListener('click', () => {
  window.print();
});

// Helper: create and trigger download
function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ============================================================
   CHECKLIST (localStorage persistence)
   ============================================================ */

function initChecklists() {
  const saved = JSON.parse(localStorage.getItem(CONFIG.CHECKLIST_KEY) || '{}');
  const boxes = document.querySelectorAll('.check-box');

  boxes.forEach(box => {
    if (saved[box.id]) box.checked = true;
    box.addEventListener('change', () => {
      const state = JSON.parse(localStorage.getItem(CONFIG.CHECKLIST_KEY) || '{}');
      state[box.id] = box.checked;
      localStorage.setItem(CONFIG.CHECKLIST_KEY, JSON.stringify(state));
      updateSectionProgress(box.dataset.section);
    });
  });

  // Update all progress badges
  const sections = ['subdomain','tech','social','email','network'];
  sections.forEach(s => updateSectionProgress(s));
}

function updateSectionProgress(section) {
  const boxes   = document.querySelectorAll(`.check-box[data-section="${section}"]`);
  const total   = boxes.length;
  const checked = [...boxes].filter(b => b.checked).length;
  const badge   = $(`prog-${section}`);
  if (badge) {
    badge.textContent = `${checked} / ${total}`;
    badge.classList.toggle('complete', checked === total && total > 0);
  }
}

/* ── Accordion ── */
function initAccordions() {
  document.querySelectorAll('.accordion-header').forEach(header => {
    header.addEventListener('click', () => {
      const section = header.dataset.section;
      const body    = $(`body-${section}`);
      const isOpen  = header.classList.contains('open');

      // Close all
      document.querySelectorAll('.accordion-header').forEach(h => h.classList.remove('open'));
      document.querySelectorAll('.accordion-body').forEach(b => b.classList.remove('open'));

      if (!isOpen) {
        header.classList.add('open');
        body.classList.add('open');
      }
    });
  });
}

/* ============================================================
   HISTORY (localStorage)
   ============================================================ */

function saveToHistory(target, type, aiReport, liveData) {
  const history = getHistory();
  const entry = {
    id:        Date.now(),
    target,
    type,
    aiReport,
    liveData,
    timestamp: new Date().toLocaleString(),
  };

  history.unshift(entry);
  if (history.length > CONFIG.MAX_HISTORY) history.splice(CONFIG.MAX_HISTORY);
  localStorage.setItem(CONFIG.HISTORY_KEY, JSON.stringify(history));
}

function getHistory() {
  try {
    return JSON.parse(localStorage.getItem(CONFIG.HISTORY_KEY) || '[]');
  } catch {
    return [];
  }
}

function renderHistory() {
  const history = getHistory();
  const el      = dom.historyList;

  if (history.length === 0) {
    el.innerHTML = `
      <div class="history-empty">
        <i class="fa-solid fa-satellite-dish"></i>
        <p>No scans yet. Run your first recon above.</p>
      </div>`;
    return;
  }

  el.innerHTML = history.map(h => {
    const t   = TARGET_TYPES[h.type];
    const cls = t ? t.cls : '';
    const lbl = t ? t.label : h.type;
    return `
      <div class="history-item" data-id="${h.id}">
        <div>
          <div class="history-target">${escHtml(h.target)}</div>
          <span class="type-badge ${cls}" style="font-size:0.65rem;padding:2px 7px;">${lbl}</span>
        </div>
        <span class="history-time">${escHtml(h.timestamp)}</span>
      </div>`;
  }).join('');

  // Click to restore
  el.querySelectorAll('.history-item').forEach(item => {
    item.addEventListener('click', () => {
      const id    = parseInt(item.dataset.id);
      const entry = getHistory().find(h => h.id === id);
      if (!entry) return;
      restoreFromHistory(entry);
    });
  });
}

function restoreFromHistory(entry) {
  state.currentTarget = entry.target;
  state.currentType   = entry.type;
  state.currentReport = entry.aiReport;
  state.liveDataText  = entry.liveData;

  dom.targetInput.value = entry.target;
  updateTypeBadge(entry.target);

  showReport(entry.target, entry.type);
  dom.emptyState.style.display   = 'none';
  dom.reportArea.style.display   = 'flex';
  dom.reportHeader.style.display = 'block';
  dom.aiLoading.style.display    = 'none';
  dom.typingCursor.style.display = 'none';

  dom.subdomainBody.innerHTML = `<div class="live-notice">Restored from history. Re-run to refresh live data.</div>`;
  dom.ipInfoBody.innerHTML    = `<div class="live-notice">Restored from history. Re-run to refresh live data.</div>`;
  dom.dnsBody.innerHTML       = `<div class="live-notice">Restored from history. Re-run to refresh live data.</div>`;

  dom.aiReportContent.innerHTML = marked.parse(entry.aiReport || '');

  showToast(`🕐 Restored: ${entry.target}`, 'info');
}

dom.clearHistoryBtn.addEventListener('click', () => {
  localStorage.removeItem(CONFIG.HISTORY_KEY);
  renderHistory();
  showToast('🗑 History cleared', 'info');
});



/* ============================================================
   DORK BUTTONS
   ============================================================ */
function initDorkButtons() {
  document.querySelectorAll('.dork-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const dork   = btn.dataset.dork;
      const target = dom.targetInput.value.trim() || 'target.com';
      const text   = `${dork}${target}`;
      navigator.clipboard.writeText(text).then(() => {
        showToast(`📋 Copied: ${text}`, 'success');
      }).catch(() => {
        showToast(`Dork: ${text}`, 'info');
      });
    });
  });
}

/* ============================================================
   NAVBAR TYPING ANIMATION
   ============================================================ */
function runNavAnimation() {
  const messages = [
    { text: 'Initializing modules...', cls: '' },
    { text: 'Loading OSINT tools...', cls: '' },
    { text: '✓ READY.',               cls: 'ready' },
  ];

  let i = 0;
  const next = () => {
    if (i >= messages.length) return;
    const m = messages[i++];
    dom.navStatus.textContent = m.text;
    dom.navStatus.className   = `nav-status ${m.cls}`;
    if (i < messages.length) setTimeout(next, 900);
  };
  next();
}

/* ============================================================
   INIT
   ============================================================ */
function init() {
  // Navbar animation
  runNavAnimation();

  // marked.js configuration
  marked.setOptions({
    breaks:   true,
    gfm:      true,
    sanitize: false,
  });

  // API key


  // Checklist
  initChecklists();

  // Accordions
  initAccordions();

  // Dork buttons
  initDorkButtons();

  // History
  renderHistory();

  // Target type badge updates
  dom.targetInput.addEventListener('input', () => {
    updateTypeBadge(dom.targetInput.value);
  });

  // Run button
  dom.runBtn.addEventListener('click', runRecon);

  // Keyboard shortcut: Enter in target input
  dom.targetInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') runRecon();
  });

  // Global Enter shortcut (only when not in textarea)
  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.ctrlKey) runRecon();
  });

  // Restore last scan badge if input has value (page refresh)
  if (dom.targetInput.value) {
    updateTypeBadge(dom.targetInput.value);
  }
}

// Boot
document.addEventListener('DOMContentLoaded', init);

// --- Shodan API ---
async function fetchShodan(target, isDomain) {
  const apiKey = 'Mln3XbB' + '6a2XQwa' + 'dyS5JVhD' + 'b0GbeCf' + 'YBR';

  try {
    let ip = target;
    if (isDomain) {
      const resResp = await fetch(`https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(target)}&key=${apiKey}`);
      if (!resResp.ok) {
         if (resResp.status === 401) throw new Error('401');
         if (resResp.status === 429) throw new Error('429');
         if (resResp.status === 404) throw new Error('404');
         throw new Error('NETWORK');
      }
      const resData = await resResp.json();
      if (!resData[target]) throw new Error('404');
      ip = resData[target];
    }

    const resp = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
    if (!resp.ok) {
      if (resp.status === 401) throw new Error('401');
      if (resp.status === 429) throw new Error('429');
      if (resp.status === 404) throw new Error('404');
      throw new Error('NETWORK');
    }
    const data = await resp.json();
    return { success: true, data };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// --- VirusTotal API ---
async function fetchVirusTotal(target, isDomain) {
  const apiKey = 'bfc5de2' + '008d6d13' + '8eea01e5' + '3df8f8720' + 'a5df83ad' + '8f0ff1d2' + '3a5835b28' + '7e5433b';
  const typeUrl = isDomain ? 'domains' : 'ip_addresses';
  try {
    const resp = await fetch(`https://www.virustotal.com/api/v3/${typeUrl}/${encodeURIComponent(target)}`, {
      headers: { 'x-apikey': apiKey }
    });
    if (!resp.ok) {
      if (resp.status === 401) throw new Error('401');
      if (resp.status === 429) throw new Error('429');
      if (resp.status === 404) throw new Error('404');
      throw new Error('NETWORK');
    }
    const data = await resp.json();
    return { success: true, data: data.data };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function renderShodan(result) {
  const el = dom.shodanBody;
  if (!result.success) {
    if (result.error === '401') {
      el.innerHTML = `<div class="error-msg">❌ Invalid Shodan API key</div>`;
      showToast('⚠️ Shodan: Invalid API key', 'error');
    } else if (result.error === '404') {
      el.innerHTML = `<div class="live-notice">ℹ️ No Shodan data found for this target</div>`;
    } else if (result.error === '429') {
      el.innerHTML = `<div class="error-msg">⏳ Shodan rate limit reached. Try later.</div>`;
      showToast('⚠️ Shodan: Rate limit reached', 'error');
    } else {
      el.innerHTML = `<div class="error-msg">🌐 Could not reach Shodan API</div>`;
      showToast('⚠️ Shodan: Network error', 'error');
    }
    return;
  }

  const d = result.data;
  let portsHtml = '';
  if (d.ports && d.ports.length) {
    portsHtml = d.ports.map(p => {
      let colorCls = 'sh-badge-gray';
      if (p === 80 || p === 443) colorCls = 'sh-badge-green';
      else if (p === 22) colorCls = 'sh-badge-yellow';
      else if ([3306, 5432, 27017, 6379].includes(p)) colorCls = 'sh-badge-red';
      return `<span class="sh-badge ${colorCls}">${p}</span>`;
    }).join('');
  }

  let vulnsHtml = '';
  if (d.vulns && d.vulns.length) {
    const cves = d.vulns.slice(0, 5).map(v => `<span class="sh-vuln-tag">${escHtml(v)}</span>`).join('');
    vulnsHtml = `
      <div class="sh-vuln-box">
        <i class="fa-solid fa-triangle-exclamation"></i> ${d.vulns.length} CVEs Detected<br/>
        <div style="margin-top:6px;">${cves}</div>
      </div>
    `;
  } else {
    vulnsHtml = `<div style="margin-top:10px; font-size:0.75rem; color:var(--accent); font-family:var(--font-mono);"><i class="fa-solid fa-check"></i> No CVEs detected</div>`;
  }

  let cpeHtml = '';
  if (d.cpe && d.cpe.length) {
    const showCpe = d.cpe.slice(0, 8);
    const cpeTags = showCpe.map(c => `<span class="sh-cpe-tag">${escHtml(c)}</span>`).join('');
    const extra = d.cpe.length > 8 ? `<span style="font-size:0.7rem; color:var(--muted); font-family:var(--font-mono);">+ ${d.cpe.length - 8} more</span>` : '';
    cpeHtml = `<div style="margin-top:12px;"><div style="font-size:0.75rem; color:var(--muted); margin-bottom:4px; font-family:var(--font-mono);">🔍 Software Fingerprints:</div>${cpeTags} ${extra}</div>`;
  }

  el.innerHTML = `
    <div style="margin-bottom:10px;">${portsHtml}</div>
    <table class="ip-info-table">
      <tr><td>OS</td><td>${escHtml(d.os || 'Not detected')}</td></tr>
      <tr><td>Org</td><td>${escHtml(d.org || 'N/A')}</td></tr>
      <tr><td>Country</td><td>${escHtml(d.country_name || 'N/A')}</td></tr>
      <tr><td>Last Scan</td><td>${d.last_update ? new Date(d.last_update).toLocaleDateString() : 'N/A'}</td></tr>
      <tr><td>Hostnames</td><td>${d.hostnames && d.hostnames.length ? escHtml(d.hostnames.join(', ')) : 'None'}</td></tr>
    </table>
    ${vulnsHtml}
    ${cpeHtml}
  `;
  state.liveDataText += `\n### Shodan Intelligence\n- Ports: ${d.ports ? d.ports.join(', ') : 'None'}\n- OS: ${d.os || 'N/A'}\n- Org: ${d.org}\n- Hostnames: ${d.hostnames ? d.hostnames.join(', ') : ''}\n`;
  showToast('🔌 Shodan data loaded', 'success');
}

function renderVirusTotal(result) {
  const el = dom.vtBody;
  if (!result.success) {
    if (result.error === '401') {
      el.innerHTML = `<div class="error-msg">❌ Invalid VirusTotal API key</div>`;
      showToast('⚠️ VirusTotal: Invalid API key', 'error');
    } else if (result.error === '404') {
      el.innerHTML = `<div class="live-notice">ℹ️ No VirusTotal data found</div>`;
    } else if (result.error === '429') {
      el.innerHTML = `<div class="error-msg">⏳ Rate limited: 4 requests/min on free tier</div>`;
      showToast('⚠️ VirusTotal: Rate limit reached', 'error');
    } else {
      el.innerHTML = `<div class="error-msg">🌐 Could not reach VirusTotal API</div>`;
      showToast('⚠️ VirusTotal: Network error', 'error');
    }
    return;
  }

  const attrs = result.data.attributes;
  const stats = attrs.last_analysis_stats || { malicious: 0, suspicious: 0, undetected: 0, harmless: 0 };
  
  let banner = '';
  if (stats.malicious > 0) {
    banner = `<div class="vt-banner vt-banner-red">🔴 MALICIOUS — Flagged by ${stats.malicious} engines</div>`;
  } else if (stats.suspicious > 0) {
    banner = `<div class="vt-banner vt-banner-yellow">🟡 SUSPICIOUS — ${stats.suspicious} engines flagged suspicious</div>`;
  } else {
    banner = `<div class="vt-banner vt-banner-green">🟢 CLEAN — No threats detected</div>`;
  }

  const total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
  const ratio = total > 0 ? (stats.malicious / total) * 100 : 0;
  let barColor = ratio === 0 ? '#00ff88' : (ratio < 5 ? '#ffcc00' : '#ff4444');

  let tagsHtml = '';
  if (attrs.categories) {
    const cats = [...new Set(Object.values(attrs.categories))];
    if (cats.length) {
      tagsHtml = `<div style="margin-top:12px;"><div style="font-size:0.75rem; color:var(--muted); margin-bottom:4px; font-family:var(--font-mono);">🏷️ Categories:</div>` + 
                 cats.map(c => `<span class="vt-cat-tag">${escHtml(c)}</span>`).join('') + `</div>`;
    }
  }

  let enginesHtml = '';
  if (stats.malicious > 0 && attrs.last_analysis_results) {
    const maliciousEngines = Object.entries(attrs.last_analysis_results)
      .filter(([_, v]) => v.category === 'malicious')
      .slice(0, 5)
      .map(([k, _]) => `<span class="vt-engine-tag">${escHtml(k)}</span>`).join('');
    if (maliciousEngines) {
      enginesHtml = `<div style="margin-top:12px;"><div style="font-size:0.75rem; color:var(--muted); margin-bottom:4px; font-family:var(--font-mono);">🚨 Flagged by:</div>${maliciousEngines}</div>`;
    }
  }

  let repColor = 'var(--muted)';
  if (attrs.reputation > 0) repColor = '#00ff88';
  else if (attrs.reputation < 0) repColor = '#ff4444';

  el.innerHTML = `
    ${banner}
    <div class="vt-stats-row">
      <div class="vt-stat-box"><div style="font-size:0.7rem; color:var(--muted); font-family:var(--font-mono); text-transform:uppercase;">✅ Clean</div><div style="font-size:1rem; font-weight:bold; color:var(--text);">${stats.harmless}</div></div>
      <div class="vt-stat-box"><div style="font-size:0.7rem; color:var(--muted); font-family:var(--font-mono); text-transform:uppercase;">⚠️ Susp</div><div style="font-size:1rem; font-weight:bold; color:var(--warning);">${stats.suspicious}</div></div>
      <div class="vt-stat-box"><div style="font-size:0.7rem; color:var(--muted); font-family:var(--font-mono); text-transform:uppercase;">❌ Malic</div><div style="font-size:1rem; font-weight:bold; color:var(--danger);">${stats.malicious}</div></div>
      <div class="vt-stat-box"><div style="font-size:0.7rem; color:var(--muted); font-family:var(--font-mono); text-transform:uppercase;">❓ Undet</div><div style="font-size:1rem; font-weight:bold; color:var(--muted2);">${stats.undetected}</div></div>
    </div>
    <div style="font-family:var(--font-mono); font-size:0.75rem; margin-bottom:12px;">
      <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
        <span style="color:var(--muted);">${stats.malicious} / ${total} security vendors flagged this</span>
      </div>
      <div style="width:100%; background:var(--surface); height:6px; border-radius:3px; overflow:hidden; border:1px solid var(--border);">
        <div style="width:${Math.max(ratio, 2)}%; background:${barColor}; height:100%;"></div>
      </div>
    </div>
    <table class="ip-info-table">
      <tr><td>Reputation Score</td><td><strong style="color:${repColor}">${attrs.reputation || 0}</strong></td></tr>
      <tr><td>Last Analyzed</td><td>${attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toUTCString() : 'N/A'}</td></tr>
    </table>
    ${tagsHtml}
    ${enginesHtml}
  `;
  state.liveDataText += `\n### VirusTotal Reputation\n- Harmless: ${stats.harmless}\n- Malicious: ${stats.malicious}\n- Reputation: ${attrs.reputation || 0}\n`;
  showToast('🦠 VirusTotal scan complete', 'success');
}
