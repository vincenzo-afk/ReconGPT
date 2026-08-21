# Contributing to ReconGPT

ReconGPT is an evidence-first, passive reconnaissance workbench. Contributions are welcome when they improve analyst clarity, source provenance, safety controls, performance, accessibility, or maintainability without weakening the project's public-only and authorization-aware boundaries.

## Ground rules

Before opening a large feature proposal, create an issue describing the analyst problem, the intended data-source boundary, and the expected privacy or safety impact. Do not add active scanning, authentication bypasses, credential collection, direct `.onion` access, message collection, hidden-identity inference, or features that require the application to retain sensitive source material without an explicit retention design.

Do not include API keys, session data, customer data, personally sensitive targets, or unredacted investigation results in issues, pull requests, fixtures, screenshots, or commits.

## Development setup

The project is verified with Node.js 22 and pnpm 10.4.1. Install dependencies from the repository root:

```bash
pnpm install --frozen-lockfile
```

For account-backed local work, configure the environment described in the [README](./README.md#getting-started), apply the database migrations, and start the development server:

```bash
pnpm db:push
pnpm dev
```

Provider-backed collectors are optional. Leave provider credentials unset unless you are authorized to use them, and never add `.env` files to version control.

## Make a focused change

Use a short-lived branch named for the type and purpose of the change, for example `fix/source-health-copy` or `feat/policy-signal-module`. Keep a pull request narrowly scoped and preserve the project's typed contracts, consent gates, retention labels, evidence-quality metadata, and target-aware module selection.

When modifying TypeScript or user-facing behavior, add or update deterministic Vitest coverage. Use approved public test targets such as `example.com` for end-to-end validation. Live provider checks are opt-in and must not be used as routine CI.

## Verify before opening a pull request

Run the commands below from the repository root:

```bash
pnpm test
pnpm check
pnpm build:vercel
```

Formatting is available through Prettier. To avoid unrelated churn, format only files you changed:

```bash
pnpm exec prettier --write path/to/changed-file.ts
```

## Pull requests

Use an imperative Conventional Commit-style subject such as `feat: add source health explanation` or `fix: preserve evidence limitation labels`. The pull-request template asks for the analyst-facing effect, verification commands, documentation changes, migrations/configuration, and safety impact.

Maintainers may request a narrower scope, a source-policy explanation, an additional regression test, or a revised retention/consent design before merging.

## Reporting security issues

Do not disclose exploitable security details in a public issue. Use the repository’s GitHub private vulnerability-reporting channel and follow the process in [SECURITY.md](./SECURITY.md).
