# ReconGPT

> AI-powered OSINT reconnaissance assistant for domains, IPs, emails, usernames, and companies — combining live intelligence collection with structured AI-generated recon workflows.






## Overview

ReconGPT is a browser-based reconnaissance and OSINT tool that takes a target, detects its type automatically, collects live intelligence from multiple external sources, and generates a structured recon report with actionable methodology, tools, commands, and risk analysis.[1]
It supports five target classes — Domain, IP Address, Email, Username, and Company — and uses different report logic and workflows for each one instead of treating every input the same way.[1]

## What it does

- Accepts a single target input and auto-detects whether it is a domain, IP, email, username, or company name.[1]
- Pulls live data from external intelligence sources before generating the report, so the AI can work with real context instead of only generic assumptions.[1]
- Produces long-form structured markdown reports with sections like target summary, passive recon steps, active recon steps, attack surface analysis, and risk assessment.[1]
- Distinguishes between confirmed data, inferred data, and unavailable data using visible confidence tags such as `✅ CONFIRMED`, `⚠️ UNCONFIRMED`, and `❌ UNAVAILABLE` in the reporting flow shown in the code.[1]
- Keeps a small local scan history and includes export actions like copy, markdown export, HTML export, and print in the UI logic already present in the app structure.[1]

## Core features

### 1. Automatic target detection

ReconGPT detects the target type from the input pattern and switches the entire workflow accordingly.[1]

| Target Type | Detection Basis | Example |
|---|---|---|
| IP Address | IPv4 regex match | `8.8.8.8` |
| Email | Email regex match | `name@example.com` |
| Domain | Domain regex match | `example.com` |
| Company | Contains spaces / organization-style input | `OpenAI Research` |
| Username | Fallback non-matching identifier | `bharani007` |

### 2. AI-generated recon reports

The app builds a separate expert prompt for each target type and asks the model to generate a professional OSINT report with fixed sections and investigation paths.[1]
For example, the domain workflow asks for subdomain attack surface, tech stack fingerprinting, social engineering surface, email pattern discovery, and risk level assessment, while the IP workflow focuses more on network intelligence, routing, threat intel, pivot opportunities, and reverse resolution.[1]

### 3. Live intelligence gathering

The code shows live fetchers for real-world data collection such as subdomains from crt.sh, DNS lookups from HackerTarget, IP enrichment, reverse DNS, email DNS records, HIBP breach checks, and AbuseIPDB reputation checks.[1]
This means ReconGPT is not only a report writer; it is also an intelligence collector that feeds those findings into the report generation pipeline.[1]

### 4. Structured evidence tagging

The reporting system is designed to separate confirmed data from AI inference.[1]
That is especially important for recon work, because the IP and email prompts explicitly instruct the model not to overstate breach findings or threat severity unless supporting live data exists.[1]

### 5. Export and workflow utilities

The interface includes controls for copying the report, exporting markdown, exporting HTML, printing the report, managing recent history, and maintaining analyst checklists in browser storage.[1]
These features make the project usable as an analyst workspace, not just a one-shot prompt box.[1]

## Supported recon modes

### Domain reconnaissance

For domain targets, ReconGPT is built to help with broad attack surface mapping and passive-first discovery.[1]

- Subdomain collection via certificate transparency sources.[1]
- DNS record collection and parsing.[1]
- Domain-to-IP resolution.[1]
- Technology fingerprinting recommendations.[1]
- Email pattern discovery guidance.[1]
- Social engineering surface mapping.[1]
- Risk-oriented summary of likely exposure areas.[1]

### IP reconnaissance

For IP targets, ReconGPT shifts into network and infrastructure analysis mode.[1]

- IP geolocation and organization context.[1]
- ASN / ISP / hosting indicators.[1]
- Reverse DNS collection.[1]
- Port and service scanning guidance.[1]
- Threat reputation checks such as AbuseIPDB.[1]
- Pivoting opportunities like related infrastructure and neighboring assets.[1]

### Email reconnaissance

For email targets, the workflow becomes identity- and breach-focused rather than network-focused.[1]

- Breach intelligence checks when supported by configured data sources.[1]
- Domain mail-security analysis using MX, SPF, DKIM, and DMARC checks.[1]
- Identity correlation from the local-part naming pattern.[1]
- Social engineering surface analysis.[1]
- Related email enumeration ideas and pattern analysis.[1]

### Username reconnaissance

For usernames, the app emphasizes cross-platform identity tracing.[1]

- Platform enumeration strategy.[1]
- Cross-platform correlation methodology.[1]
- Content analysis guidance for forum/posts/search-engine lookup.[1]
- Breach and digital footprint mapping suggestions.[1]

### Company reconnaissance

For companies, ReconGPT expands from single-target recon into organizational intelligence.[1]

- Digital asset discovery for domains, IP ranges, and owned infrastructure.[1]
- Employee and org-chart OSINT workflows.[1]
- Email harvesting and pattern discovery.[1]
- Physical and location intelligence ideas.[1]
- Vendor and third-party exposure review.[1]

## Built-in data sources and modules

The current code clearly references several external intelligence sources and recon modules.[1]

| Module / Source | Purpose |
|---|---|
| `crt.sh` | Certificate Transparency subdomain discovery.[1] |
| `HackerTarget` | DNS lookups, host search, and related recon utilities.[1] |
| `AbuseIPDB` | Abuse reputation scoring for IPs.[1] |
| `Have I Been Pwned` | Breach lookup for email intelligence.[1] |
| Reverse DNS | PTR resolution for IP analysis.[1] |
| Email DNS parsing | MX, SPF, DMARC, DKIM review for email domains.[1] |
| Groq API | LLM-based streaming report generation using `llama-3.3-70b-versatile` in the current config.[1] |

## Report structure

ReconGPT does not return random text blocks; it asks the model for fixed report sections tailored to the input category.[1]
From the code, the section sets include items such as:

- Target Summary.[1]
- Recommended Tools & Commands.[1]
- Passive Recon Steps.[1]
- Active Recon Steps.[1]
- Threat Intelligence Checks.[1]
- Attack Surface Summary.[1]
- Risk Level Assessment.[1]

That structure makes the output useful for bug bounty work, OSINT investigation, pentest preparation, and analyst note-taking.[1]

## User interface features

The front-end code indicates a fairly complete analyst UI rather than a minimal demo.

- Target input with live type badge.
- Context input for analyst-provided notes.
- API key fields for selected services.
- Expandable module cards for different recon categories.
- Dedicated live-data panels for DNS, IP, subdomains, AI report body, and threat-related modules.
- Report action buttons for copy, markdown, HTML, and print.
- History panel with clear-history support.

## Technical highlights

- Browser-based JavaScript architecture with a centralized app state object storing current target, report, live data, and recon metadata.
- Groq chat completions endpoint configured for streaming LLM output with a max token budget of 4096 in the current config block.
- Prompt engineering differs by target type, which is a strong design choice for recon tools because domains, IPs, emails, and usernames need different methodologies.
- The code keeps metadata about fetched and failed sources, which is useful for transparent reporting and export.

## Use cases

- Bug bounty reconnaissance.
- Passive OSINT collection before manual testing.
- Attack surface discovery.
- Email and identity investigation.
- Corporate target profiling.
- Analyst workflow acceleration with AI-assisted reporting.

## Why this project is useful

Most recon tools either automate collection or generate advice, but ReconGPT is designed to combine both into one workflow.[1]
That makes it useful for people who want a live-data-assisted recon companion that can both gather evidence and suggest what to do next in a structured way.[1]

## Quick start

```bash
git clone https://github.com/your-username/ReconGPT.git
cd ReconGPT
```

- Open the project in a simple local server environment, because browser-based apps that call APIs usually work better over HTTP than direct `file://` loading.
- Add your API keys where needed.
- Enter a target.
- Review the live data panels.
- Generate and export the report.

Example local server options:

```bash
python -m http.server 8000
```

Then open:

```bash
http://localhost:8000
```

## Suggested repo sections

You can also add these small files around the README for a stronger repo setup based on your usual clean-project style.[2]

- `LICENSE`
- `.gitignore`
- `.env.example`
- `docs/ARCHITECTURE.md`
- `docs/API_KEYS.md`
- `screenshots/`
- `demo/`

## README tagline options

Pick one of these for the repo subtitle:

- `AI-powered OSINT recon for domains, IPs, emails, usernames, and companies.`
- `Browser-based reconnaissance assistant with live intelligence and structured AI reporting.`
- `Modern OSINT workflow tool combining live data collection with analyst-grade AI reports.`

## Topics for GitHub

```txt
osint, recon, reconnaissance, cybersecurity, pentesting, bugbounty, javascript, groq, llm, threat-intelligence, dns, subdomain-enumeration, email-intelligence, ip-intelligence
```

## License

MIT is a good fit if you want the project to stay easy to use, fork, and extend in public open-source workflows.

## Disclaimer

Use ReconGPT only for authorized security research, defensive analysis, lab work, education, or targets you own or have permission to assess.