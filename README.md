# ReconGPT

**ReconGPT** is a fullstack, evidence-first OSINT workspace for authorized public-information reconnaissance. It provides a dark mission-control interface, a terminal-like target command bar, an AI analyst chat, server-sent live module events, stored operations, entity relationships, and exportable reports.

> ReconGPT is designed for legitimate research, asset inventory, incident response, and authorized security assessment. It intentionally avoids active port scanning, credential collection, mailbox access, social engineering, authentication bypass, and retrieval of restricted leak content.

## What it collects

| Area | Passive collection included |
|---|---|
| Domain and infrastructure | crt.sh names, DNS and email-authentication records, RDAP, public TLS metadata, HTTP response posture, and common CDN/technology signals. |
| IP intelligence | Reverse DNS, public geolocation/ASN context, and historical provider intelligence from IPinfo, AbuseIPDB, Shodan, and VirusTotal when configured. |
| Identity research | Email-domain posture, a 100+ platform username candidate matrix, public GitHub profiles/repositories/gists, and carefully labelled public research pivots. |
| Historical and web intelligence | Wayback URL history, document-like URL inventory, robots.txt, sitemap.xml, security.txt, urlscan history, and public search-query workspaces. |
| Corporate, ASN, and phone research | Public registry, career, trademark, routing, peering, and non-enriching public-search pivots. |

## Architecture

Recon runs are authenticated, server-orchestrated operations. The browser opens a protected **SSE** stream under `/api/recon/stream`; the server validates and normalizes the target, executes applicable passive modules sequentially, persists module events/findings/entities/relationships, streams each state transition, and returns the completed evidence bundle. The UI never receives provider secrets.

The normalized database model stores `recon_runs`, `recon_events`, `recon_entities`, `entity_relationships`, and per-analyst settings. Stored runs can be reviewed, compared, re-run, and exported as Markdown, JSON, or printable HTML.

## Secure provider configuration

Provider credentials must be injected through the project’s secure secret settings—not committed to source code and never pasted into the client application. The supported server-side variables are shown below.

| Environment variable | Provider |
|---|---|
| `SHODAN_API_KEY` | Shodan historical host intelligence |
| `VIRUSTOTAL_API_KEY` | VirusTotal domain/IP reputation |
| `ABUSEIPDB_API_KEY` | AbuseIPDB IP reputation |
| `URLSCAN_API_KEY` | urlscan.io authenticated history access (optional for public search) |
| `IPINFO_TOKEN` | IPinfo network and geolocation context |
| `EXTERNAL_LLM_API_KEY` | Reserved for a separately configured external LLM provider; built-in evidence analysis remains available by default. |

ReconGPT surfaces **configured/not configured** state only. It deliberately does not show, serialize, export, or prefill raw credential values.

## Local development

Install dependencies and start the development server with the following commands.

```bash
pnpm install
pnpm dev
```

Run static checks and the test suite before deployment.

```bash
pnpm check
pnpm test
```

## Analyst workflow

Sign in, choose the authorized target and research depth, then launch a passive run from the terminal command bar. Module progress appears as live event cards. Review source-linked findings in the evidence explorer, inspect target-connected entities in the filterable graph, compare stored runs when monitoring an asset, and generate a report only after validating the evidence and engagement scope.

## Provider and source links

ReconGPT uses public or user-configured provider APIs and sources including [crt.sh](https://crt.sh/), [RDAP](https://www.icann.org/rdap), [Internet Archive CDX](https://archive.org/help/wayback_api.php), [Shodan](https://developer.shodan.io/), [VirusTotal](https://docs.virustotal.com/), [AbuseIPDB](https://docs.abuseipdb.com/), [urlscan.io](https://urlscan.io/docs/api/), and [IPinfo](https://ipinfo.io/developers). Analysts remain responsible for compliance with each provider’s terms and for ensuring their research is authorized.
