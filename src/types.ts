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

/** Raw response from GET /skill/trust-score/{did}. */
export interface SignedTrustScoreResponse {
  did: Did;
  score: number | null;
  grade: string | null;
  computed_at: string;
  valid_until: string;
  withheld: boolean;
  /** Detached signature over the JCS canonicalisation of all fields except `registry_signature`. */
  registry_signature: {
    kid: string;
    alg: 'Ed25519';
    /** Hex-encoded Ed25519 signature. */
    signature: string;
  };
}

/** Result of a successful verification. */
export interface VerifiedTrustScore {
  did: Did;
  score: number | null;
  grade: string | null;
  computed_at: Date;
  /** Score expiry. `EnforcementGate` refuses to use the score past this. */
  valid_until: Date;
  withheld: boolean;
  /** Which `kid` signed this score. */
  signed_by: string;
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
