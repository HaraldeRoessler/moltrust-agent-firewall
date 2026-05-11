# Security Policy

`@moltrust/agent-firewall` is the consumer-side library for the MolTrust trust
registry. Trust-related vulnerabilities have direct impact on agents'
authorisation decisions, so we treat reports seriously.

## Reporting a vulnerability

**Please do NOT open a public GitHub issue for security problems.**

### Preferred: GitHub private vulnerability reporting

Use the **"Report a vulnerability"** button on the repo's Security tab:

  https://github.com/HaraldeRoessler/moltrust-agent-firewall/security/advisories/new

This creates a private advisory visible only to the maintainer and your
GitHub account. It supports back-and-forth discussion, draft patches,
and a coordinated public disclosure.

### What to include

- Affected version(s) of `@moltrust/agent-firewall`
- Short description of the issue
- Steps to reproduce (or a minimal proof-of-concept)
- Impact: what an attacker can achieve, under what conditions
- Suggested fix or mitigation, if you have one

## Response timeline

| Stage | Target |
| --- | --- |
| Acknowledgement of receipt | 72 hours |
| Initial triage + severity classification | 7 days |
| Fix for critical issues | 24-48 hours from confirmation |
| Fix for high issues | 14 days |
| Fix for medium / low | next minor release |

These are targets, not contractual commitments — complex issues take
longer to fix correctly than incorrectly.

## Coordinated disclosure

We follow a **90-day disclosure window**, counted from the date a
valid report is acknowledged. The process is:

1. We confirm receipt and start investigation.
2. We develop a fix and run it through the full test + smoke-test
   suite, plus any incremental review the issue warrants.
3. We agree a release date with the reporter.
4. We ship the fix, publish a GitHub Security Advisory (and request
   a CVE / GHSA where appropriate), and credit the reporter in the
   release notes unless they prefer to remain anonymous.

If 90 days is insufficient (e.g. the issue requires upstream
registry-side changes), we'll coordinate an extension transparently
with the reporter rather than letting the clock run out silently.

Please don't publicly disclose before a fix ships — it harms every
consumer of the package.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |
| < 1.0   | ❌        |

Security fixes target the latest published 1.x minor. Pre-1.0
tags exist only as development snapshots and are not eligible
for security patches.

## Scope

### In scope

- The published `@moltrust/agent-firewall` npm package and source code
  in this repository.
- Vulnerabilities that let an attacker:
  - Forge or replay verified trust scores
  - Bypass `EnforcementGate` allow/deny decisions
  - Exhaust memory or CPU via crafted registry responses
  - Inject HTTP request headers, smuggle requests, or perform
    response-splitting / DNS-rebinding tricks
  - Cause unintended state changes on the host (file write, network
    fan-out, etc.) via library code paths
  - Defeat the cryptographic guarantees of `MoltrustVerifier`
    (JCS canonicalisation, Ed25519 verification, `valid_until`
    enforcement)

### Out of scope

- **Issues in the upstream MolTrust registry** (`api.moltrust.ch`,
  `MoltyCel/moltrust-api`). Those belong to the registry maintainer
  — please report to `kersten.kroehl@cryptokri.ch` or the
  `MoltyCel/moltrust-api` repo's own security channels.
- **Issues in transitive dependencies** (`@noble/curves`,
  `canonicalize`). Please report upstream first; we'll coordinate a
  re-release here if needed.
- **Behaviour in configurations that explicitly disable security
  features.** The library emits a `process.emitWarning` whenever
  these are set:
  - `dangerouslyAllowHttp: true`  (HTTP allowed)
  - `allowExpired: true`           (expired scores accepted)
  - `dropUnsignedEvents: false`    (unsigned CAEP events trusted)
  Operators who opt in have taken explicit responsibility.
- **Theoretical attacks requiring local code execution or root
  access on the consumer host.** If an attacker can already execute
  arbitrary code, the library's invariants don't help.
- **Denial-of-service via legitimate, well-formed API usage.** The
  library exposes options (`maxWatchedDids`, `maxEntries`,
  `maxDenylistSize`, `intervalMs`) for callers to bound resource
  usage. Misconfiguration is an operational concern, not a security
  one.

## Cryptographic posture

This library defends end-to-end against forged trust scores:

- **RFC 8785 (JCS)** canonical JSON via [`canonicalize`](https://www.npmjs.com/package/canonicalize)
- **Ed25519** verification via [`@noble/curves`](https://github.com/paulmillr/noble-curves) (audited, no native deps)
- Strict JWK validation: `kty=OKP`, `crv=Ed25519`, `alg=EdDSA`, 32-byte public key
- `valid_until` enforced on every signed score (override is opt-in and warned)
- Registry public-key discovery via `/.well-known/registry-key.json`,
  with TTL clamped to `[60s, 24h]`
- `kid`-keyed key cache provides a grace window across key rotation

CAEP Profile v1 events (`did_revoked`, `flag_added`, `flag_removed`)
are **not signed in the current protocol** — authenticity rests on
TLS to `api.moltrust.ch`. See [PROFILE.md](./PROFILE.md#event-authenticity)
for the explicit threat model and mitigations. This is a documented
protocol limitation, not a library defect. Library defaults
(`dropUnsignedEvents: true`) suppress typed handlers for these
events unless the operator explicitly opts in.

## Hall of fame

Reporters credited here once we receive our first valid disclosure.

— Harald Roessler, maintainer
