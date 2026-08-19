# ReconGPT

> **A public-evidence casefile for mapping an authorized attack surface without turning reconnaissance into an active scan.**

[![License: MIT](https://img.shields.io/badge/license-MIT-9fe8d6.svg)](./LICENSE)
[![Collection](https://img.shields.io/badge/collection-40%20passive%20modules-9fe8d6.svg)](#module-catalogue)
[![Transport](https://img.shields.io/badge/live%20updates-server--sent%20events-9fe8d6.svg)](#the-data-path)
[![UI](https://img.shields.io/badge/interface-React%2019-9fe8d6.svg)](#technology-notes)

**[Browse the source](https://github.com/vincenzo-afk/ReconGPT)** · **[Report a defect](https://github.com/vincenzo-afk/ReconGPT/issues)** · **[Request a change](https://github.com/vincenzo-afk/ReconGPT/issues)**

---

## <a name="contents"></a>Contents

- [The brief](#the-brief)
- [The data path](#the-data-path)
- [Technology notes](#technology-notes)
- [Getting started](#getting-started)
- [Operating a case](#operating-a-case)
- [Module catalogue](#module-catalogue)
- [Service interface](#service-interface)
- [Project map](#project-map)
- [What is shipped](#what-is-shipped)
- [Verification](#verification)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [Security, consent, and scope](#security-consent-and-scope)
- [License](#license)
- [Acknowledgments and references](#acknowledgments-and-references)

---

## <a name="the-brief"></a>The brief

ReconGPT is built for the first practical question in an investigation: **what can be corroborated from public information, and what still needs a human to validate?** It accepts a domain, IP address, URL, email address, username, organization, phone number, or autonomous system number (ASN), then selects the passive collectors that apply to the target.

The interface is deliberately a **casefile**, not a generic dashboard. The analyst moves from scope, to collection, to corroboration, to graph inspection, to a report that preserves both evidence and its gaps. Runs stream their own progress through server-sent events (SSE), an HTTP push channel that keeps long-running recon visible without a polling loop.[1]

ReconGPT does not present a source snippet as proof. Findings carry evidence-quality and lead-status labels, source counts, freshness, limitations, data sensitivity, consent basis, and retention class. The assistant is instructed to distinguish evidence from inference and to avoid intrusive follow-up instructions.

| Surface | What it is for |
|---|---|
| Mission control | Set authorized scope, research depth, and a target-aware collection plan. |
| Live telemetry | Watch queued, started, completed, notice, and failed module events. |
| Evidence explorer | Filter findings, open public-source links, and inspect raw detail and limitations. |
| Entity graph | Filter node types, expand a node, and review linked finding provenance. |
| History and delta view | Reopen preserved cases and compare finding families or risk-score movement. |
| Report desk | Export JSON, Markdown, or a printable HTML casefile with coverage context. |

---

## <a name="the-data-path"></a>The data path

```mermaid
flowchart LR
  A[Analyst casefile<br/>React + Tailwind] -->|tRPC| B[Application router]
  A -->|authenticated SSE| C[Recon stream]
  B --> D[Settings, history, AI, media metadata]
  C --> E[Target parser and consent gates]
  E --> F[Passive module orchestrator]
  F --> G[Public sources and optional provider APIs]
  F --> H[Evidence normalizer<br/>risk, provenance, limitations]
  H --> I[Run event stream]
  H --> J[(MySQL / TiDB<br/>Drizzle)]
  J --> K[Run history and entity graph]
  I --> A
  K --> A
```

The browser uses typed tRPC procedures for application operations and the dedicated authenticated stream for run events.[2] The server normalizes results before storage, keeping runs, events, entities, relationships, and analyst settings distinct in the relational model. Drizzle provides the typed MySQL schema and migration layer.[3]

### Evidence vocabulary

| Label | Meaning in a ReconGPT result |
|---|---|
| `direct` | A first-party or directly returned public source supports the record. |
| `corroborated` | Independent public sources point in the same direction. |
| `context` | Useful surrounding information that does not establish the assertion alone. |
| `lead` | A pivot that needs analyst review before it is treated as evidence. |

These labels are collection metadata, not a substitute for authorization, legal review, or human validation.

---

## <a name="technology-notes"></a>Technology notes

| Layer | Declared implementation |
|---|---|
| Client | React 19.2.1, Vite 7.1.7, TypeScript 5.9.3, Tailwind CSS 4.1.14, React Query 5.90.2 |
| Server | Express 4.21.2, tRPC 11.6.0, Zod 4.1.12, Server-Sent Events |
| Persistence | Drizzle ORM 0.44.5 with MySQL/TiDB through `mysql2` 3.15.0 |
| Collection helpers | Cheerio 1.2.0, `robots-parser` 3.0.1, `tldts` 7.4.10, `exifr` 7.1.3 |
| Presentation | `react-markdown` 10.1.0 with `remark-gfm` 4.0.1, Lucide, and bespoke casefile CSS |
| Verification | Vitest 2.1.4, TypeScript compiler checks, Vite/esbuild production build |

Shodan, VirusTotal, AbuseIPDB, urlscan.io, and IPinfo are optional server-side providers. A missing key reduces source coverage; it does not expose a key or create a result.

---

## <a name="getting-started"></a>Getting started

### Prerequisites

The repository is verified with **Node.js 22** and **pnpm 10.4.1**. A MySQL-compatible database is required for account-backed run history, event persistence, graph storage, and preferences. OAuth configuration is required for authenticated operator flows.

```bash
git clone https://github.com/vincenzo-afk/ReconGPT.git
cd ReconGPT
pnpm install
```

For a self-hosted setup, inject the server configuration through the host environment. Do not commit `.env` files or copy a provider token into browser code.

```dotenv
# Account-backed operation
DATABASE_URL=mysql://USER:PASSWORD@HOST:3306/recongpt
VITE_APP_ID=YOUR_OAUTH_APPLICATION_ID
JWT_SECRET=LONG_RANDOM_SERVER_SIDE_SECRET
OAUTH_SERVER_URL=YOUR_OAUTH_SERVER_URL

# Platform or analysis integration when applicable
OWNER_OPEN_ID=OPTIONAL_OWNER_OPEN_ID
BUILT_IN_FORGE_API_URL=OPTIONAL_PLATFORM_FORGE_URL
BUILT_IN_FORGE_API_KEY=OPTIONAL_PLATFORM_FORGE_KEY
EXTERNAL_LLM_API_KEY=OPTIONAL_SERVER_SIDE_ANALYSIS_KEY

# Optional passive-provider modules
SHODAN_API_KEY=OPTIONAL_SHODAN_KEY
VIRUSTOTAL_API_KEY=OPTIONAL_VIRUSTOTAL_KEY
ABUSEIPDB_API_KEY=OPTIONAL_ABUSEIPDB_KEY
URLSCAN_API_KEY=OPTIONAL_URLSCAN_KEY
IPINFO_API_KEY=OPTIONAL_IPINFO_TOKEN
```

`IPINFO_TOKEN` is accepted as a backward-compatible alternative to `IPINFO_API_KEY`. Only the server reads provider and analysis credentials.

```bash
pnpm db:push
pnpm dev
```

### Configuration ledger

| Variable | Required | Purpose |
|---|---:|---|
| `DATABASE_URL` | Yes for persistence | MySQL/TiDB connection used by Drizzle and migration commands. |
| `VITE_APP_ID`, `JWT_SECRET`, `OAUTH_SERVER_URL` | Yes for authenticated use | OAuth identity, signed-session secret, and OAuth server address. |
| `OWNER_OPEN_ID` | No | Gives the configured owner the application admin role at sign-in. |
| `BUILT_IN_FORGE_API_URL`, `BUILT_IN_FORGE_API_KEY` | Platform-dependent | Server-side platform-service connection. |
| `EXTERNAL_LLM_API_KEY` | No | Server-side alternative analysis credential. |
| `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `URLSCAN_API_KEY`, `IPINFO_API_KEY` | No | Enables the matching passive provider. |

---

## <a name="operating-a-case"></a>Operating a case

1. **Sign in** and open **Operations**. History, preferences, AI chat, image metadata inspection, and reports are scoped to the analyst.
2. Enter an authorized target and, when useful, a concise scope note. Choose **Focused**, **Balanced**, or **Deep**. Depth changes bounded research budgets; it does not authorize active scanning.
3. Review **Settings** before launching. Module selection is stored per analyst and the collection grid updates for the target type.
4. Confirm the authorization statements that apply. Email posture, user-provided image metadata, and community-control pathways have additional gates.
5. Launch the case. Read the live stream for rate limits, source gaps, and failed sources; an empty source is not proof of absence.
6. Inspect findings and source health, then pivot through the graph only from evidence in the run. Export after reviewing the limitations.

The report formats preserve executive assessment, findings, an evidence-quality ledger, source-health/release-signal notes, source coverage, limitations, privacy labels, and degraded-persistence warnings when they apply.

---

## <a name="module-catalogue"></a>Module catalogue

The registry contains **40 passive modules**. Selectors are target-aware: a phone module will not run for a domain. The optional-provider label means a server-side key is required.

<details>
<summary><strong>Open the complete collection catalogue</strong></summary>

| ID | Collector | Case area | Targets | Notes |
|---|---|---|---|---|
| `crt-subdomains` | Certificate Transparency | Domain | Domain, URL | Public certificate naming evidence. |
| `dns-posture` | DNS & Mail Posture | Domain | Domain, URL, email | DNS and mail-policy posture. |
| `email-disclosure` | Email & Disclosure Posture | Domain | Domain, URL, email | Public disclosure and contact context. |
| `dns-crosscheck` | DNS-over-HTTPS Cross-check | Domain | Domain, URL, email | Resolver cross-check for DNS evidence. |
| `rdap-whois` | RDAP / WHOIS | Domain | Domain, URL | Registration-record context. |
| `tls-certificate` | TLS Certificate | Infrastructure | Domain, URL | Public certificate attributes. |
| `certificate-timeline` | Certificate Change Timeline | Historical | Domain, URL | Certificate history and changes. |
| `http-fingerprint` | HTTP Fingerprint | Infrastructure | Domain, URL | Public HTTP response posture. |
| `ipinfo` | IPinfo Geo & ASN | IP intelligence | Domain, URL, IP | Optional IPinfo provider. |
| `reverse-ptr` | Reverse DNS PTR | IP intelligence | Domain, URL, IP | Reverse DNS context. |
| `routed-prefix` | BGP Prefix & Owner | IP intelligence | Domain, URL, IP | Public routing prefix and owner context. |
| `network-ownership-context` | Routing & RPKI Context | IP intelligence | Domain, URL, IP | Routing and origin-validation context. |
| `abuseipdb` | AbuseIPDB | IP intelligence | Domain, URL, IP | Optional AbuseIPDB provider. |
| `shodan` | Shodan Passive Services | IP intelligence | Domain, URL, IP | Optional Shodan provider; no active probing. |
| `virustotal` | VirusTotal Reputation | Threat intelligence | Domain, URL, IP | Optional VirusTotal provider. |
| `urlscan` | urlscan.io History | Web intelligence | Domain, URL | Optional urlscan.io public-history provider. |
| `wayback` | Wayback History | Historical | Domain, URL | Archived URL presence. |
| `historical-web-change` | Public Web Change Timeline | Historical | Domain, URL | Public-web history comparison context. |
| `common-crawl` | Common Crawl Index | Historical | Domain, URL | Public Common Crawl index references. |
| `public-search` | Free Public Search | Research | Domain, URL, organization | Bounded public-search discovery. |
| `public-web-crawl` | Robots-aware Web Crawl | Web intelligence | Domain, URL | Bounded, robots-aware first-party public-page read. |
| `public-policy-surface` | Public Policy & Release Signals | Web intelligence | Domain, URL | Public policy and release-document signals. |
| `structured-web-provenance` | Structured-Web Provenance | Web intelligence | Domain, URL | Publisher-supplied structured-data context. |
| `research-dorks` | Research Query Builder | Research | Domain, URL, organization | Analyst-ready public query pivots. |
| `public-web-surface` | Public Web Surface | Web intelligence | Domain, URL | Initial public-web surface context. |
| `document-metadata` | Document HTTP Metadata | Document intelligence | URL | HTTP-level document metadata only. |
| `exposure-research` | Exposure Research Pivots | Research | Domain, URL | Analyst research leads. |
| `public-advisory-pivots` | Public Advisory Pivots | Threat intelligence | Domain, URL, organization | Public advisory and research leads. |
| `defensive-brand-leads` | Defensive Brand Leads | Brand intelligence | Domain, URL, organization | Defensive lookalike and brand-monitoring leads. |
| `username-matrix` | Username Matrix | Identity | Username | Username pivot matrix. |
| `username-presence` | Bounded Username Presence | Identity | Username | Bounded checks plus manual review links across a versioned 100+ platform catalogue. |
| `public-social-profile-links` | Public Social Profile Links | Social intelligence | Username | Public profile-link adapters only. |
| `github-supply-chain` | GitHub Supply Chain | Supply chain | Username | Public repository and advisory pivots. |
| `email-context` | Email Posture | Identity | Email | Email/domain context; not ownership proof. |
| `email-ownership-posture` | Consent-bound Email Posture | Identity | Email | Requires explicit email-authorization confirmation. |
| `onion-index-leads` | Onion-index Research Lead | Threat intelligence | Domain, URL, organization, email | Produces public research leads; does not connect to `.onion` services. |
| `community-integration-status` | Community Integration Status | Community intelligence | Domain, organization, username | Disabled-by-default Discord/Telegram control status; no connector is started. |
| `corporate-research` | Corporate Pivots | Corporate | Organization | Public corporate research pivots. |
| `phone-research` | Phone Research Pivots | Identity | Phone | Public research pivots, not subscriber or carrier lookup. |
| `asn-research` | ASN Research Pivots | IP intelligence | ASN | Autonomous-system research pivots. |

</details>

### Special handling paths

| Path | Guardrail |
|---|---|
| Email posture | The analyst confirms ownership or authorization before the consent-bound path runs. Results remain posture signals, not account-ownership proof. |
| Username presence | Automated checks are bounded by research depth. Any listed platform presence still requires analyst review. |
| Image metadata | A user-authorized upload is parsed ephemerally and the original image is not retained. |
| Social and onion research | Public profile links and onion-index results are reviewable leads. No direct `.onion` access occurs. |
| Discord and Telegram | Administrator-gated configuration only. The application does not start a connector, discover members, or collect messages. |

---

## <a name="service-interface"></a>Service interface

ReconGPT’s first-class interface is the signed-in workspace. tRPC handles account, settings, history, AI, and media operations; the dedicated SSE route handles a run because it produces a sequence of progress events rather than one response.

| Surface | Access | Purpose |
|---|---|---|
| `GET /api/recon/stream` | Authenticated | Launches a recon stream from `target`, `context`, `dorkIntensity`, `modules`, and consent flags. Emits JSON in SSE `data:` frames. |
| `recon.modules` | Public | Lists module metadata, target applicability, and provider-key requirements. |
| `recon.list`, `recon.get`, `recon.compare` | Authenticated | Lists, retrieves, and compares a user’s stored runs. |
| `settings.get`, `settings.save` | Authenticated | Reads and persists module choices, research depth, and preferred model. |
| `settings.saveCommunity`, `settings.purgeCommunity` | Administrator | Maintains selected-scope community settings and audit history. |
| `ai.chat` | Authenticated | Runs the evidence-first analyst assistant with a bounded message history. |
| `media.inspectMetadata` | Authenticated | Parses authorized JPEG, PNG, WebP, or TIFF metadata without retaining the original upload. |

Stream consumers must already satisfy the application session. Treat the stream as an authenticated, user-scoped operation rather than a public scraping endpoint.

---

## <a name="project-map"></a>Project map

```text
ReconGPT/
├── client/
│   └── src/
│       ├── pages/Home.tsx              # Mission-control casefile
│       ├── pages/casefile.css          # Graphite/mint visual system
│       ├── components/ReconGraph.tsx   # Filterable, inspectable entity graph
│       └── lib/reportExport.ts         # JSON, Markdown, printable HTML reports
├── server/
│   ├── _core/                          # Runtime, OAuth, tRPC, Vite integration
│   ├── recon/
│   │   ├── modules.ts                  # Passive collector registry and source safeguards
│   │   ├── service.ts                  # Orchestration, normalization, grounded summary
│   │   ├── routes.ts                   # Authenticated SSE recon endpoint
│   │   ├── identitySafety.ts           # Consent, retention, redaction, community guards
│   │   ├── usernamePresence.ts         # Bounded 100+ platform presence catalogue
│   │   └── mediaMetadata.ts            # Ephemeral EXIF/image metadata extraction
│   ├── db.ts                           # Persistence helpers
│   └── routers.ts                      # tRPC application surface
├── drizzle/
│   ├── schema.ts                       # MySQL/Drizzle schema
│   └── 0000_*.sql … 0004_*.sql         # Tracked migrations
├── ideas.md                            # Product and visual-direction notes
├── package.json                        # Scripts and dependencies
└── vitest.config.ts                    # Test runner configuration
```

---

## <a name="what-is-shipped"></a>What is shipped

The current release includes a casefile interface, 40 target-aware passive collectors, authenticated live streaming, source coverage and health ledgers, evidence-quality normalization, constrained AI analysis, preserved history, entity relationships, a filterable graph, three report formats, module preferences, consent-led identity collection, and administrator-only community-control configuration.

It also has deliberate boundaries. ReconGPT does not perform port scanning, credential attacks, exploitation, social engineering, direct dark-web access, message collection, or hidden identity resolution. Public sources can be incomplete, stale, rate-limited, or unavailable; the coverage ledger keeps those gaps visible.

There is no separate committed roadmap document. Changes should be proposed through GitHub issues and preserve the passive, evidence-first operating model.

---

## <a name="verification"></a>Verification

Run the deterministic suite, compiler check, and production bundle check from the repository root.

```bash
pnpm test
pnpm check
NODE_OPTIONS='--max-old-space-size=768' pnpm build
```

Vitest covers target parsing, source-safety controls, orchestration resilience, evidence normalization, report generation, identity consent, media policy, username budgets, and community controls.[4] The ordinary suite does not contact third-party provider APIs.

In a secure environment with the provider secrets configured, an operator can intentionally enable the credential smoke path:

```bash
RUN_LIVE_PROVIDER_TESTS=true pnpm vitest run server/recon/providerCredentials.test.ts
```

This call reaches configured providers. Do not run it in an unapproved environment or paste its credentials into logs.

---

## <a name="deployment"></a>Deployment

ReconGPT ships without a Dockerfile or external-platform deployment manifest. Its production path is the Node build already declared in `package.json`: install dependencies, inject the server environment, apply migrations, build the Vite client and bundled Node server, then start the process.

```bash
pnpm install --frozen-lockfile
pnpm db:push
NODE_OPTIONS='--max-old-space-size=768' pnpm build
NODE_ENV=production pnpm start
```

The runtime needs the database, OAuth, and optional provider-secret configuration from [Getting started](#getting-started). The development preview is intentionally not listed as a public homepage because it is not a durable shareable deployment. Publish the checkpoint through the project management interface before adding the resulting production URL to the repository metadata.

---

## <a name="contributing"></a>Contributing

Open an issue before a large change so the scope can be checked against the project’s passive-collection and consent boundaries. Keep changes focused, add or update a Vitest case when behavior changes, and run the three verification commands before opening a pull request.

Use short, imperative commit subjects. Conventional Commit prefixes such as `feat:`, `fix:`, `test:`, and `docs:` are preferred because they make release history easier to read. A pull request should explain analyst-facing impact, source or safety implications, tests run, and any migration or secret requirement.

---

## <a name="security-consent-and-scope"></a>Security, consent, and scope

ReconGPT is a reconnaissance workbench, not a license to investigate any target. Operators remain responsible for authorization, local law, contractual limits, and the terms of public sources. The collection model is intentionally bounded: public-web reads are size-limited and robots-aware, provider calls are server-side, and research pivots are labelled as leads when they require validation.

Secrets stay behind the server environment boundary. The UI exposes configured state rather than key material, and the repository should never contain `.env` files, API keys, session tokens, or personally sensitive collected data. If a security problem is found, do not publish exploitable details in a public issue; contact the repository owner privately through the GitHub account below with reproduction details and impact.

Identity features have stricter handling. Email ownership confirmation, supplied-media authorization, and community-administrator confirmation must be made explicitly. Community controls are configuration scaffolding only: they support pause, purge, retention, and audit metadata but do not activate a bot or retain community messages.

---

## <a name="license"></a>License

ReconGPT is released under the [MIT License](./LICENSE). Copyright © 2026 **vincenzo-afk**.

---

## <a name="acknowledgments-and-references"></a>Acknowledgments and references

ReconGPT uses React, tRPC, Drizzle ORM, Vite, Vitest, and the public-source services selected by an analyst’s environment. The project’s visual and product posture is set out in [`ideas.md`](./ideas.md), and the operational source of truth for collectors is [`server/recon/modules.ts`](./server/recon/modules.ts).

| Reference | Resource |
|---|---|
| [1] | [MDN: Server-sent events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events) |
| [2] | [tRPC documentation](https://trpc.io/docs) |
| [3] | [Drizzle ORM documentation](https://orm.drizzle.team/docs/overview) |
| [4] | [Vitest guide](https://vitest.dev/guide/) |

---

<p align="center">
  <a href="#contents">Back to top</a> ·
  <a href="https://github.com/vincenzo-afk/ReconGPT">GitHub</a>
</p>

<p align="center">Built with care by <strong>vincenzo-afk</strong>.</p>
