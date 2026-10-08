## What and why

<!-- One paragraph: the problem and the change. Link the issue. -->

## How it was verified

<!-- Commands you ran and their results, e.g. `npm test` (counts), `npm run demo` (PASS line), `npm run test:postgres`. -->

## Checklist

- [ ] Commits are signed off (`git commit -s`, Developer Certificate of Origin)
- [ ] `npm run build && npm test` passes; Postgres-touching changes also pass `npm run test:postgres`
- [ ] `npm run demo` ends with `PASS`
- [ ] Contract changes: `npm run docs:contract` was run and `docs/contract.md` prose updated; `CONTRACT_VERSION` considered
- [ ] Docs and playbooks updated for any changed command, output or exit code
- [ ] `CHANGELOG.md` has an entry under "Unreleased"
- [ ] Security review checklist in `CONTRIBUTING.md` answered below for changes to auth, storage, outbound requests, validation or logging
- [ ] No credentials, keys, real host names or personal data in code, tests, fixtures or docs

## Security notes

<!-- New inputs, privileges, outbound calls, stored data; or "none". -->
