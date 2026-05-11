# MolTrust CAEP Profile v1

**Status:** v1 — proprietary, polling-only, not OpenID SET.

The MolTrust registry at `api.moltrust.ch` emits trust-relevant events
about registered agents (trust-score changes, revocations, flag
updates). The "MolTrust CAEP Profile v1" is the wire format and
delivery semantics for those events.

> **Naming note.** "CAEP" overlaps with the OpenID Foundation's
> *Continuous Access Evaluation Profile* (part of the Shared Signals
> Framework, RFC drafts `draft-ietf-secevent-*`). The MolTrust profile
> is **unrelated** to that work. It is not a Security Event Token (SET,
> RFC 8417), it is not a JWT, and OpenID SSF receivers will not parse
> it correctly. Do not feed these events into an OpenID SET pipeline.

## Endpoints

All endpoints are on the registry origin (default
`https://api.moltrust.ch`):

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`  | `/caep/pending/{did}?since={evt_id}&limit={n}` | Returns pending events for `did`. Cursor-based. Default limit 100, max 500. Rate limit: **120 polls/h per DID** (a 30-second interval is exactly at the cap). |
| `POST` | `/caep/acknowledge/{event_id}` | Soft-ack. Acked events are retained for 90 days but not redelivered. Idempotent. |
| `GET`  | `/.well-known/registry-key.json` | The registry's current Ed25519 signing key as a JWK (`kty=OKP`, `crv=Ed25519`, `alg=EdDSA`, `kid=moltrust-registry-2026-v1`). `Cache-Control: max-age=3600` is honoured. |
| `GET`  | `/skill/trust-score/{did}` | Signed trust-score response (see "Signed trust scores" below). |

## Event format

```jsonc
{
  "event_id": "evt_018f4...",         // stable per registry
  "subject_did": "did:moltrust:abc",  // who this event is about
  "event_type": "trust_score_change", // see "Event types" below
  "emitted_at": "2026-05-11T17:42:00Z",
  "payload": {                        // type-specific
    "old_score": 70,
    "new_score": 82,
    "grade": "A",
    "recomputed_at": "2026-05-11T17:42:00Z"
  }
}
```

`/caep/pending/{did}` returns:

```jsonc
{
  "events": [ /* ... CaepEvent[] ... */ ],
  "has_more": false,
  "next_cursor": "evt_018f4..."        // null when events[] is empty
}
```

## Event types

| Type | Status in v1 | Payload shape (informative) |
| --- | --- | --- |
| `trust_score_change` | **Live.** Emitted by the registry when the recomputed Phase-2 score moves by ≥ 10 points. | `{ old_score, new_score, grade, recomputed_at }` |
| `did_revoked` | **Reserved.** Will be emitted once the registry's admin revocation tool ships (OOS for Phase 0). | `{ reason?, revoked_at }` |
| `flag_added` / `flag_removed` | **Reserved.** Requires the `caep_flag_snapshot` table (Phase 0.5). | `{ flag, set_at?, cleared_at? }` |

Consumers MUST tolerate unknown `event_type` values without erroring —
forward compatibility for future types is built in.

### Event authenticity

> **⚠️ Important.** CAEP Profile v1 events are **not individually
> signed**. The wire format is plain JSON, not a JWS / JWT / SET.
> Authenticity rests on the TLS channel to `api.moltrust.ch`.

This library handles the gap as follows:

- **`trust_score_change`** is the **only event type that's
  cryptographically validated end-to-end**. On receipt, the client
  re-fetches `GET /skill/trust-score/{did}` and runs full
  JCS + Ed25519 verification before emitting the typed event.
  A network attacker who fabricates a `trust_score_change` cannot
  influence the score the caller observes — only trigger an
  extra signed-score fetch (denial-of-budget concern at most).
- **`did_revoked`** and **`flag_added` / `flag_removed`** are
  passed through as received. A compromised proxy between the
  consumer and the registry could, in principle, fabricate them.
  The client **defaults to `dropUnsignedEvents: true`** — typed
  handlers fire only for cryptographically-verified events.
  Operators who need to act on these unsigned events can opt in
  with `dropUnsignedEvents: false`; the client emits a Node
  `MoltrustInsecureEventsWarning` on start in that mode.
- The registry roadmap includes signed CAEP envelopes; once
  shipped, that work will land here as **Profile v2** with a
  documented migration path.

## Signed trust scores

`GET /skill/trust-score/{did}` returns a payload of the form:

```jsonc
{
  "did": "did:moltrust:abc",
  "score": 82,                       // 0–100, or null when withheld
  "grade": "A",                      // or null
  "computed_at": "2026-05-11T17:42:00Z",
  "valid_until": "2026-05-11T18:42:00Z",
  "withheld": false,                 // true if Phase 2 has < 3 unique endorsers
  "registry_signature": {
    "kid": "moltrust-registry-2026-v1",
    "alg": "Ed25519",
    "signature": "<hex>"             // Ed25519 sig (64 bytes, hex-encoded)
  }
}
```

The signing input is the **RFC 8785 (JCS) canonicalisation** of every
field above **except `registry_signature`**. Verifiers must:

1. Look up the public key for `registry_signature.kid` via
   `/.well-known/registry-key.json` (with sensible caching).
2. Strip `registry_signature` from the response.
3. JCS-canonicalise the remainder.
4. Ed25519-verify the canonicalised bytes against the published
   public key.
5. Reject if the local clock is past `valid_until` (the registry's
   recomputation cadence guarantees fresh values within the cache
   window).

This library does all five steps in `MoltrustVerifier`.

## Polling cadence guidance

- The rate limit is **120 polls/hour per DID**, enforced server-side.
- A 30-second polling interval is exactly at the cap; the library
  clamps `intervalMs` to `>= 30000` to avoid 429s.
- For most firewalls, **30–60s is right.** The registry emits
  `trust_score_change` only on ≥ 10-point swings, so sub-minute
  polling rarely captures anything new.
- On 429, the library obeys `Retry-After` and exponentially backs
  off (jittered) per affected DID.
- For DIDs that may accumulate event backlogs (e.g. after a long
  outage), set `pageLimit: 500` (the registry maximum) so each
  poll drains as much as possible. The library does NOT poll
  faster than the rate-limit window even when `has_more: true` —
  high-throughput catch-up should come from larger pages, not
  from increased request frequency.

## Future channels

`v1` supports polling only. The library exposes an `EventSource`
interface so future channels (e.g. the **XMTP push channel
planned for Q2/Q3 2026**) can be slotted in without changing the
`MoltrustCaepClient` API. Consumers binding only to the public
surface here will receive XMTP-delivered events automatically once
that source becomes available.

## What this profile is NOT

- **Not OpenID SSF / CAEP / RISC.** No SET envelope, no JWT, no
  iss/aud/iat claims in the OpenID sense.
- **Not WebSub / WebHooks.** The registry does not push to caller
  endpoints in v1 — polling only.
- **Not a generic event bus.** Only the four event types listed
  above are defined, and only `trust_score_change` is currently
  emitted in production.

If MolTrust later aligns this profile with OpenID SSF (e.g. by
wrapping events in SETs), it will be published as `v2` with a
distinct profile identifier and a documented migration path.
