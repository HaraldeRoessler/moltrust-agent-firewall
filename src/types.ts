/**
 * Profile identifier for the wire protocol implemented by this library.
 *
 * MolTrust CAEP Profile v1 is a MolTrust-proprietary event format
 * for trust-score changes, revocations, and flag updates emitted by
 * api.moltrust.ch. It is NOT the OpenID Foundation Shared Signals
 * Framework / Continuous Access Evaluation Profile (CAEP) — the name
 * overlap is coincidental. Do not feed these events to an OpenID SET
 * receiver.
 */
export const PROFILE_ID = 'MolTrust CAEP Profile v1';
export const PROFILE_VERSION = '1';

/** Default registry base URL — overridable per client. */
export const DEFAULT_REGISTRY = 'https://api.moltrust.ch';

/** Expected `kid` for the current registry signing key. */
export const DEFAULT_KID = 'moltrust-registry-2026-v1';

/** Registry rate limit: GET /caep/pending/{did} is capped per DID. */
export const RATE_LIMIT_PER_HOUR_PER_DID = 120;

/** A registered MolTrust DID. */
export type Did = string;

/**
 * CAEP event types emitted by the MolTrust registry.
 *
 * Phase 0 emits `trust_score_change` only. `did_revoked`,
 * `flag_added`, and `flag_removed` are reserved in the wire format
 * but not yet emitted by api.moltrust.ch (per PR #15 backlog).
 */
export type CaepEventType =
  | 'trust_score_change'
  | 'did_revoked'
  | 'flag_added'
  | 'flag_removed';

/** Raw CAEP event payload from GET /caep/pending/{did}. */
export interface CaepEvent {
  /** Event identifier (`evt_<id>`). Stable per registry. */
  event_id: string;
  /** The subject DID this event is about. */
  subject_did: Did;
  /** Event type. */
  event_type: CaepEventType;
  /** ISO 8601 timestamp of when the registry emitted the event. */
  emitted_at: string;
  /** Type-specific payload. Free-form on the wire. */
  payload: Record<string, unknown>;
}

/**
 * Convenience typed payload for `trust_score_change`. The registry
 * emits this when the recomputed score moves by >= 10 points.
 */
export interface TrustScoreChangePayload {
  old_score: number | null;
  new_score: number;
  grade: string | null;
  recomputed_at: string;
}

/**
 * Reserved payload shape for `did_revoked` (not yet emitted; the
 * registry's admin revocation tool is OOS for Phase 0).
 */
export interface DidRevokedPayload {
  reason?: string;
  revoked_at: string;
}

/**
 * Reserved payload shape for flag events (requires
 * `caep_flag_snapshot` table — Phase 0.5).
 */
export interface FlagPayload {
  flag: string;
  set_at?: string;
  cleared_at?: string;
}

/** Result of GET /caep/pending/{did}. */
export interface CaepPendingResponse {
  events: CaepEvent[];
  /** When `true`, more events are available — caller should poll again with `since=<last event_id>`. */
  has_more: boolean;
  /** Echoed last event_id for the next `since` cursor. */
  next_cursor: string | null;
}

/** Raw response from `GET /skill/trust-score/{did}` (matches `api.moltrust.ch` wire format). */
export interface SignedTrustScoreResponse {
  did: Did;
  /** 0..100, or `null` when withheld (Phase 2 requires ≥3 unique endorsers). */
  trust_score: number | null;
  /** A/B/C/D/N/A/REVOKED — the registry's grading. */
  grade: string | null;
  /** Free-form breakdown of how the score was computed (informational). */
  breakdown?: Record<string, unknown>;
  endorser_count?: number;
  withheld: boolean;
  flags?: string[];
  flag_count?: number;
  computed_at: string;
  /** Alias for `valid_until` used by older endpoints; ignored when both are present. */
  cache_valid_until?: string;
  /** When the score expires. The verifier rejects responses where this is in the past. */
  valid_until: string;
  consistency_level?: string;
  evaluation_context: {
    /** Identifies the scoring policy under which the response was signed. Part of the signed payload. */
    policy_version: string;
    evaluated_at?: number;
    cache_valid_seconds?: number;
  };
  /**
   * Base64url-encoded Ed25519 signature (64 raw bytes → ~86 chars, no padding).
   *
   * The signature covers the JCS canonicalisation of a five-field minimal
   * payload (NOT the whole response): `{did, trust_score, computed_at,
   * valid_until, policy_version}`. The `kid` is implicit — every signature
   * is produced by `moltrust-registry-2026-v1`, looked up via
   * `/.well-known/registry-key.json`.
   */
  registry_signature: string;
}

/** Result of a successful verification. */
export interface VerifiedTrustScore {
  did: Did;
  trust_score: number | null;
  grade: string | null;
  computed_at: Date;
  /** Score expiry. `EnforcementGate` refuses to use the score past this. */
  valid_until: Date;
  withheld: boolean;
  /** Which `kid` signed this score (always `moltrust-registry-2026-v1` for the current registry). */
  signed_by: string;
  /** The scoring policy version that was signed (e.g. `phase2`). */
  policy_version: string;
  /** Verification timestamp (when the local clock saw the signature pass). */
  verified_at: Date;
}

/** Public registry signing key, fetched from /.well-known/registry-key.json. */
export interface RegistryKey {
  kid: string;
  alg: 'Ed25519';
  /** Raw Ed25519 public key (32 bytes). */
  publicKey: Uint8Array;
  /** RFC 7517 JWK envelope as received. */
  raw: JsonWebKey;
  /** When this key was fetched. */
  fetchedAt: Date;
  /** When this cached key should be considered stale (from response Cache-Control). */
  expiresAt: Date;
}

/** RFC 7517 JWK as returned by the registry endpoint. */
export interface JsonWebKey {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string; // base64url-encoded 32-byte public key
  kid: string;
  alg: 'EdDSA';
  use?: 'sig';
}

/**
 * Pluggable persistence for poll cursors and pending acknowledgments.
 *
 * The library bundles `MemoryStore` (in-process Map) as the default.
 * Production deployments needing fault-tolerance should provide a
 * Redis- or DB-backed implementation.
 */
export interface Store {
  /** Returns the last `event_id` we processed for this DID, or null on first poll. */
  getCursor(did: Did): Promise<string | null>;
  /** Persists the new cursor after successfully processing a batch. */
  setCursor(did: Did, cursor: string): Promise<void>;
  /** Records that we still owe the registry an acknowledgment for this event_id. */
  enqueueAck(eventId: string): Promise<void>;
  /** Returns and clears all pending acks (called periodically by the client). */
  drainAcks(): Promise<string[]>;
}

/** Errors thrown by this library are instances of MoltrustFirewallError. */
export class MoltrustFirewallError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public override readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'MoltrustFirewallError';
  }
}
