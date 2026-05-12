/* ============================================================
   RECONGPT — recon.service.js
   Centralized API service for all live fetches.
   Handles timeouts, fallbacks, error handling, Promise.allSettled
   ============================================================ */

const RECON_CONFIG = {
  TIMEOUT: 8000,  // 8 seconds
  FALLBACK_CMD_PREFIX: 'Manual check: ',
};

/**
 * Wrapper for fetch with timeout and structured error handling
 * @param {string} url
 * @param {object} options
 * @returns {Promise<{success: boolean, data?: any, error?: string, fallback_cmd?: string}>}
 */
async function timedFetch(url, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), RECON_CONFIG.TIMEOUT);

  try {
    const resp = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeoutId);

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }

    const data = await resp.json();
    return { success: true, data };
  } catch (err) {
    clearTimeout(timeoutId);

    let message = 'Failed to fetch';
    let fallback_cmd = '';

    if (err.name === 'AbortError') {
      message = 'Request timed out';
    } else if (err.message.includes('HTTP')) {
      message = `API error: ${err.message}`;
    } else {
      message = `Network error: ${err.message}`;
    }

    // Generate fallback command based on URL
    if (url.includes('ipinfo.io')) {
      fallback_cmd = `${RECON_CONFIG.FALLBACK_CMD_PREFIX}curl "${url}"`;
    } else if (url.includes('ip-api.com')) {
      fallback_cmd = `${RECON_CONFIG.FALLBACK_CMD_PREFIX}curl "${url}"`;
    } else if (url.includes('dns.google')) {
      fallback_cmd = `${RECON_CONFIG.FALLBACK_CMD_PREFIX}curl "${url.replace('https://dns.google/resolve?', 'dig @8.8.8.8 ')}"`;
    } else if (url.includes('haveibeenpwned.com')) {
      fallback_cmd = `${RECON_CONFIG.FALLBACK_CMD_PREFIX}curl -H "hibp-api-key: YOUR_KEY" "${url}"`;
    } else if (url.includes('abuseipdb.com')) {
      fallback_cmd = `${RECON_CONFIG.FALLBACK_CMD_PREFIX}curl -H "Key: YOUR_KEY" "${url}"`;
    } else {
      fallback_cmd = `${RECON_CONFIG.FALLBACK_CMD_PREFIX}curl "${url}"`;
    }

    return { success: false, error: message, fallback_cmd };
  }
}

// --- IP Info Fetch (Bug #1) ---
async function fetchIPInfo(ip) {
  // Primary: ipinfo.io with token
  const ipinfoToken = (typeof SECRETS !== 'undefined' && SECRETS.ipinfoToken) || process.env.IPINFO_TOKEN || 'YOUR_IPINFO_TOKEN';
  if (ipinfoToken && ipinfoToken !== 'YOUR_IPINFO_TOKEN') {
    const result = await timedFetch(`https://ipinfo.io/${ip}/json?token=${ipinfoToken}`);
    if (result.success) {
      const d = result.data;
      return {
        success: true,
        data: {
          query: ip,
          country: d.country,
          countryCode: d.country,
          regionName: d.region,
          city: d.city,
          isp: d.org || 'N/A',
          org: d.org || 'N/A',
          as: `AS${d.asn || ''} ${d.org || ''}`,
          timezone: d.timezone,
          mobile: false,
          proxy: d.privacy ? d.privacy.proxy : false,
          hosting: d.privacy ? d.privacy.hosting : false,
        }
      };
    }
  }

  // Fallback: ip-api.com
  const fallbackResult = await timedFetch(`http://ip-api.com/json/${ip}`);
  if (fallbackResult.success) {
    const d = fallbackResult.data;
    if (d.status === 'success') {
      return {
        success: true,
        data: {
          query: ip,
          country: d.country,
          countryCode: d.countryCode,
          regionName: d.regionName,
          city: d.city,
          isp: d.isp || 'N/A',
          org: d.org || 'N/A',
          as: d.as || 'N/A',
          timezone: d.timezone,
          mobile: d.mobile,
          proxy: d.proxy,
          hosting: d.hosting,
        }
      };
    }
  }

  // Final fallback
  return { success: false, error: 'IP lookup unavailable. Run manually: curl https://ipinfo.io/' + ip + '/json?token=YOUR_TOKEN or http://ip-api.com/json/' + ip };
}

// --- Reverse DNS Lookup (Bug #2) ---
async function fetchReverseDNS(ip) {
  // Convert IP to reverse notation
  const reversed = ip.split('.').reverse().join('.') + '.in-addr.arpa';

  const result = await timedFetch(`https://dns.google/resolve?name=${encodeURIComponent(reversed)}&type=PTR`);
  if (result.success && result.data.Answer && result.data.Answer.length > 0) {
    const ptr = result.data.Answer[0].data.replace(/\.$/, ''); // Remove trailing dot
    return { success: true, data: ptr };
  }

  return { success: false, error: 'No PTR record found' };
}

// --- HIBP Breach Check ---
async function fetchHIBPBreach(email) {
  const hibpKey = (typeof SECRETS !== 'undefined' && SECRETS.hibpKey) || process.env.HIBP_API_KEY || '';
  if (!hibpKey) {
    return { success: false, error: 'HIBP API key not configured', fallback_cmd: 'curl -H "hibp-api-key: YOUR_KEY" https://haveibeenpwned.com/api/v3/breachedaccount/' + encodeURIComponent(email) };
  }

  const result = await timedFetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`, {
    headers: { 'hibp-api-key': hibpKey }
  });

  if (result.success) {
    return { success: true, data: result.data };
  }

  return { success: false, error: result.error || 'Breach check failed', fallback_cmd: result.fallback_cmd };
}

// --- DNS Records for Email (Feature #8) ---
async function fetchEmailDNS(domain) {
  const records = {};

  // MX
  const mxResult = await timedFetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`);
  records.MX = mxResult.success ? mxResult.data : { error: mxResult.error };

  // TXT (for SPF, DMARC)
  const txtResult = await timedFetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`);
  records.TXT = txtResult.success ? txtResult.data : { error: txtResult.error };

  // DKIM (common selectors)
  const dkimSelectors = ['default', 'google', 'dkim'];
  records.DKIM = {};
  for (const selector of dkimSelectors) {
    const dkimResult = await timedFetch(`https://dns.google/resolve?name=${encodeURIComponent(selector + '._domainkey.' + domain)}&type=TXT`);
    records.DKIM[selector] = dkimResult.success ? dkimResult.data : { error: dkimResult.error };
  }

  return { success: true, data: records };
}

// --- AbuseIPDB Check (Feature #9) ---
async function fetchAbuseIPDB(ip) {
  const abuseKey = (typeof SECRETS !== 'undefined' && SECRETS.abuseKey) || process.env.ABUSEIPDB_KEY || '';
  if (!abuseKey) {
    return { success: false, error: 'AbuseIPDB key not configured', fallback_cmd: 'curl -H "Key: YOUR_KEY" https://api.abuseipdb.com/api/v2/check?ipAddress=' + ip };
  }

  const result = await timedFetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
    headers: { 'Key': abuseKey }
  });

  if (result.success && result.data.data) {
    return { success: true, data: result.data.data };
  }

  return { success: false, error: result.error || 'AbuseIPDB check failed', fallback_cmd: result.fallback_cmd };
}

// Export functions
window.ReconService = {
  fetchIPInfo,
  fetchReverseDNS,
  fetchHIBPBreach,
  fetchEmailDNS,
  fetchAbuseIPDB,
};