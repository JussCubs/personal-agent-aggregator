# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. This creates a draft security advisory that only
you and the maintainers can see.

Do not open a public issue, pull request or discussion for a vulnerability,
and do not include working credentials, keys or other people's data in the
report.

Include, as far as you can:

- the affected component (core, reference server, CLIs, scripts) and version or commit;
- the storage backend and deployment shape if relevant;
- exact steps or a minimal script to reproduce, from a clean clone if possible;
- the impact you expect (which asset in the [threat model](docs/security/threat-model.md)
  is affected, and by which actor).

## What to expect

- We aim to acknowledge a report within 3 business days and to give a first
  assessment within 10 business days.
- We keep you informed while we work on a fix, agree on a disclosure date with
  you (normally within 90 days of the report), and credit you in the advisory
  unless you prefer otherwise.
- Fixes are released as patch versions and announced through a GitHub
  security advisory.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Scope

In scope: the code in this repository, deployed as documented (including the
playbooks' configuration). Examples of what we want to hear about: reading or
changing another owner's or another connection's data, bypassing scopes or
approvals, credential or secret disclosure (including through logs),
server-side request forgery, consent-page attacks, and denial of service that
one agent or address can cause despite the documented limits.

Out of scope: findings that require `AGG_ALLOW_PRIVATE_CALLBACKS=1` (a
development-only flag) or a compromised host, operator or database
administrator; vulnerabilities in an agent platform itself; missing hardening
headers on endpoints that serve no HTML; and reports from automated scanners
without a demonstrated impact.

## Safe harbor

We will not pursue or support legal action against good-faith research that
follows this policy, stays within your own deployment and test data, avoids
privacy violations and service degradation, and gives us reasonable time to
fix the issue before disclosure.
