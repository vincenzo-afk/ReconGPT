# Security Policy

## Supported release line

Security fixes are evaluated against the current `main` branch and the active Vercel deployment. The project does not maintain a parallel support policy for historical commits.

## Reporting a vulnerability

Please use the repository’s **Private vulnerability reporting** channel on GitHub. Do not open a public issue for a suspected vulnerability, credential exposure, authentication weakness, authorization bypass, data-retention flaw, or unsafe collection path.

Submit a concise report that identifies the affected component, impact, safe reproduction conditions, and any mitigations already tested. Do not include live API keys, user sessions, unredacted target data, private investigation evidence, or weaponized payloads. Use a harmless test target or a redacted proof of concept whenever possible.

The maintainer will triage reports privately. No response-time commitment is made in this repository policy.

## Scope notes

ReconGPT treats its passive-collection, consent, provenance, retention, and server-side credential boundaries as security-relevant. Reports concerning active-scanning regressions, data exposure, missing consent checks, cross-user access, secret leakage, unsafe source handling, or report-export disclosure are in scope.

Questions about a collector’s public-source boundary or a proposed safety improvement can be opened as a public issue only when no vulnerability details or sensitive data are included.
