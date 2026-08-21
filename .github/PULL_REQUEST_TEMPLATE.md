## Summary

Describe the analyst-facing change and the reason for it.

## Evidence, source, and safety impact

- [ ] This change preserves public-only and authorization-aware collection boundaries.
- [ ] I documented any new source, rate limit, consent requirement, retention effect, or evidence-quality limitation.
- [ ] This change does not introduce active scanning, credential collection, authentication bypasses, or direct `.onion` access.

## Verification

- [ ] `pnpm test`
- [ ] `pnpm check`
- [ ] `pnpm build:vercel`
- [ ] I added or updated deterministic tests where behavior changed.

## Release impact

- [ ] Documentation is updated, or no documentation change is needed.
- [ ] No migration is required.
- [ ] No environment/configuration change is required.

If a migration or configuration change is required, explain the deployment order and rollback approach below.

## Additional context

Add screenshots, redacted logs, or implementation notes when helpful. Do not include secrets, sessions, private target data, or unredacted investigation evidence.
