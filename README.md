# @moltrust/agent-firewall

> Consumer library for the MolTrust trust registry. Implements the
> **MolTrust CAEP Profile v1** (polling) and signed trust-score
> verification (RFC 8785 JCS + Ed25519).

[![npm](https://img.shields.io/npm/v/@moltrust/agent-firewall.svg)](https://www.npmjs.com/package/@moltrust/agent-firewall)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

This library lets agent operators react to events emitted by the
MolTrust registry — trust-score changes, revocations, flag updates —
and verify signed trust-score responses end-to-end without trusting
any intermediary.

For the wire-protocol description and rationale, see [`PROFILE.md`](./PROFILE.md).

## Install

```bash
npm install @moltrust/agent-firewall
```

Requires Node 18+. Pure JavaScript, no native dependencies.

## Quick start

```ts
import { MoltrustCaepClient } from '@moltrust/agent-firewall';

const client = new MoltrustCaepClient({
  // Your own agent's DID, or the counterparties you want events about.
  watch: ['did:moltrust:0000000000000000'],
});

client.on('trust_score_change', (verified, raw) => {
  console.log(
    `${verified.did} score → ${verified.score} (${verified.grade}), ` +
      `valid until ${verified.valid_until.toISOString()}`,
  );
});

client.on('did_revoked', (did) => {
  console.warn(`MolTrust revoked ${did} — invalidate any cached trust`);
});

await client.start();
// ... later
await client.stop();
```

Score changes are auto-verified (the client re-fetches
`/skill/trust-score/{did}` and runs the JCS + Ed25519 check) before
the typed event fires. Set `{ autoVerify: false }` if you want raw
events only.

## Verifying scores explicitly

```ts
import { MoltrustVerifier } from '@moltrust/agent-firewall';

const verifier = new MoltrustVerifier();
const verified = await verifier.fetchAndVerify('did:moltrust:abc');

if (verified.score !== null && verified.score >= 60) {
  // …allow
}
```

`fetchAndVerify` throws if the signature does not validate, if the
`kid` is no longer published, or if `valid_until` is in the past
(pass `{ allowExpired: true }` to relax the last check).

## Composing with `a2a-acl`

`@moltrust/agent-firewall` is intentionally orthogonal to
`a2a-acl` (the Express middleware for AAE envelope verification
and per-tool capability ACLs). A typical production stack composes
the two:

```ts
import express from 'express';
import { firewallChain, KeyResolver, TrustResolver } from 'a2a-acl';
import { MoltrustCaepClient, EnforcementGate } from '@moltrust/agent-firewall';

const caep = new MoltrustCaepClient({ watch: ['did:moltrust:abc', /* … */] });
await caep.start();

const gate = new EnforcementGate(caep, { minScore: 60 });

const app = express();
app.use(express.json());
app.use(firewallChain({
  trustResolver: new TrustResolver({
    resolve: async (did) => {
      const decision = await gate.decide(did);
      return decision.score?.score ?? 0;
    },
  }),
  // …keyResolver, revocationChecker, matchAcl wired as usual
}));
```

`EnforcementGate` is a minimal example. Most production firewalls
will want richer policy (per-tenant thresholds, allowlists,
vertical-specific rules) — treat the gate as a starting point, not
a one-size-fits-all primitive.

## Why polling-only in v1

The MolTrust registry emits `trust_score_change` events only on
≥ 10-point swings, and the score itself has a `valid_until`
horizon (typically 1h). A 30–60s polling cadence catches every
material change well within the window where it matters for an
admission decision. The 120/h-per-DID rate limit is generous for
this workload.

A push channel over **XMTP is planned for Q2/Q3 2026**. The library
exposes an `EventSource` interface; when the XMTP source ships it
will be a drop-in replacement and existing consumers will not need
code changes beyond passing `{ source: new XmtpSource(…) }` to the
client constructor.

## What it doesn't do

- **Persistent storage.** Cursors and pending acks live in process
  memory by default (`MemoryStore`). On restart the client
  re-fetches anything still in the registry's 90-day retention
  window. For HA, implement the `Store` interface against Redis
  or your DB of choice.
- **DID resolution.** The library trusts the DIDs you give it. If
  you need to verify that a DID is a properly registered MolTrust
  agent, hit `GET /identity/verify/{did}` separately.
- **Rating / endorsing.** Those are write paths against the
  registry; this library is a consumer.
- **OpenID SET conformance.** See [`PROFILE.md`](./PROFILE.md) —
  the name overlap with the OpenID Foundation's CAEP is
  coincidental and the wire format is incompatible.

## Public API

| Export | Role |
| --- | --- |
| `MoltrustCaepClient` | High-level entry point. Combines an event source, verifier, and trust cache; emits typed events. |
| `MoltrustVerifier` | Standalone score verifier — JCS + Ed25519 + `valid_until`. |
| `RegistryKeyDiscovery` | Fetches and caches `/.well-known/registry-key.json`. |
| `PollingSource` | The v1 `EventSource` implementation. |
| `EventSource` (interface) | Extension point for the Q2/Q3 XMTP source. |
| `TrustCache` | Verified-score cache with `valid_until` eviction. |
| `EnforcementGate` | Example allow/deny gate over the client + cache. |
| `MemoryStore` | Default in-process `Store` for cursors + pending acks. |
| `MoltrustFirewallError` | Discriminated error type with `code` field. |

See the inline TypeScript types for the full surface.

## Security

### Cryptographic posture

- Ed25519 signatures verified with [`@noble/curves`](https://github.com/paulmillr/noble-curves)
  (no native deps, audited).
- RFC 8785 canonicalisation via [`canonicalize`](https://www.npmjs.com/package/canonicalize).
- Strict JWK validation: `kty=OKP`, `crv=Ed25519`, `alg=EdDSA`, 32-byte key.
- `valid_until` enforced on every signed score (override per-call with `allowExpired: true`).
- Key-cache TTLs clamped to `[60s, 24h]` regardless of `Cache-Control`.

### Network posture

- **HTTPS required.** `registryUrl` is validated at construction time;
  HTTP URLs throw `MoltrustFirewallError(code: 'insecure_protocol')`
  unless `dangerouslyAllowHttp: true` is set (intended for local mocks
  only).
- **Per-request timeouts.** All HTTP calls default to a 10s deadline
  via `AbortSignal.timeout`. Override with `requestTimeoutMs`.
- **Rate-limit aware.** The polling interval is clamped to `>= 30s`
  per DID to honour the registry's 120/h-per-DID cap; `429 Retry-After`
  is obeyed.
- **DID validation at boundaries.** All public methods that take a DID
  reject malformed input (length cap 256, `did:method:identifier`
  syntax) before constructing URLs.
- **Event shape validation.** Incoming CAEP events are validated
  against a strict shape before being dispatched; malformed events
  are dropped with a warning rather than processed.

### Trust-model caveats

- **CAEP events are not signed in v1.** Only `trust_score_change` is
  validated end-to-end (the client re-fetches the signed score on
  receipt). For `did_revoked` / `flag_added` / `flag_removed`,
  authenticity rests on the TLS channel — see [PROFILE.md](./PROFILE.md#event-authenticity)
  for full details. The client **defaults to `dropUnsignedEvents: true`**
  — typed handlers fire only on verified events. Set `false` to
  opt in (emits a runtime warning).
- **Authentication credentials are bearer-equivalent.** `apiKey` is
  sent as `X-API-Key`; the equivalent `bearerToken` option sends
  `Authorization: Bearer <token>`. Either is the registry's full
  read credential for the calling agent — treat as a secret, never
  log, and rotate on suspected exposure.
- **`EnforcementGate.denylist` is in-memory by default** — it does not
  survive process restarts. Production deployments wanting durable
  revocation memory should pass their own `Set` backed by Redis or
  a DB (the gate mutates the supplied Set in place).
- **`MemoryStore` (the default cursor backend) is also in-memory.**
  After a process restart the polling client re-fetches anything
  still in the registry's 90-day retention window for every watched
  DID — operationally a thundering-herd risk at scale. For HA
  deployments, implement the `Store` interface against Redis or a DB.
- **`EnforcementGate` distinguishes transient from permanent errors.**
  Permanent (`signature_invalid`, `invalid_did`, expired score) always
  deny. Transient (`fetch_failed`, `request_timeout`, `rate_limited`,
  `http_error`) deny by default but can fail-open via
  `transientErrorPolicy: 'allow'` for high-availability gateways
  willing to trade some safety for uptime during registry outages.
- **`getVerifiedScore` is singleflight-deduplicated** — concurrent
  calls for the same DID make at most one network request. This
  bounds the rate to the registry to roughly the number of distinct
  DIDs being asked about, not the number of callers. Serial
  loops without `await` between iterations still fan out; rate-limit
  callers should still respect the registry's published per-DID limits.
- **The registry is a trusted upstream.** DID resolution, signup,
  and registration are all out of scope for this library; if you need
  to verify that a DID was legitimately registered, hit
  `GET /identity/verify/{did}` separately.

Vulnerabilities: please email `security@moltrust.ch` rather than
opening a public issue.

## License

MIT.
