import { MoltrustFirewallError, type Did, type VerifiedTrustScore } from '../types.js';
import type { MoltrustCaepClient } from '../caep/client.js';
import { assertValidDid } from '../util/security.js';

/** Error codes from `MoltrustFirewallError` that represent transient (likely retryable) failures. */
const TRANSIENT_ERROR_CODES: ReadonlySet<string> = new Set([
  'fetch_failed',
  'request_timeout',
  'rate_limited',
  'http_error',
]);

export interface GateDecision {
  allow: boolean;
  /** Machine-readable reason — stable codes for telemetry. */
  reason:
    | 'allowed'
    | 'denied_score_below_threshold'
    | 'denied_score_withheld'
    | 'denied_score_expired'
    | 'denied_revoked'
    | 'denied_signature_invalid'
    | 'denied_transient_error'
    | 'denied_unknown_error';
  /** The verified score that informed the decision, if any. */
  score: VerifiedTrustScore | null;
  /** When `allow=false` and the cause was an error, the underlying error code. */
  errorCode?: string;
}

export interface GateOptions {
  /** Minimum verified score required (0-100). Defaults to 0 (any score). */
  minScore?: number;
  /** Reject DIDs whose Phase 2 score is `withheld: true` (default true). */
  rejectWithheld?: boolean;
  /**
   * DIDs explicitly denied — typically populated by listening to
   * `client.on('did_revoked', ...)`. The default value is a fresh
   * in-memory `Set` which **does NOT survive process restarts**;
   * after a restart, previously-revoked DIDs are re-evaluated via
   * `getVerifiedScore()`.
   *
   * For deployments that require persistent denylists (HA gateways,
   * regulated environments), pass your own Set that's backed by
   * Redis / DB / disk and the gate will mutate it in place.
   */
  denylist?: Set<Did>;
  /**
   * When `getVerifiedScore` fails for a transient reason (network
   * failure, timeout, registry 5xx, rate limit), should the gate
   * fail open (allow) or fail closed (deny)?
   *
   * - `'deny'` (default): safest — registry outage stops all new
   *   authorisations until it recovers. Right for high-stakes flows.
   * - `'allow'`: highest availability — accepts the operational risk
   *   that a registry outage equals "everyone's score is whatever
   *   they last had". Right for low-stakes, high-volume flows.
   *
   * Permanent errors (invalid DID, invalid signature, expired score,
   * unknown kid) always deny regardless of this setting — they are
   * not retryable.
   */
  transientErrorPolicy?: 'allow' | 'deny';
}

/**
 * Minimal allow/deny gate over a `MoltrustCaepClient`. Use it
 * directly, or compose it into your existing Express / Fastify /
 * a2a-acl middleware stack.
 *
 * The gate is intentionally tiny — most production firewalls have
 * tenant-specific policy that doesn't belong in a shared library
 * (custom thresholds, allowlists, vertical-specific rules, etc.).
 * Treat this as a worked example more than a one-size-fits-all
 * enforcement primitive.
 */
export class EnforcementGate {
  private readonly minScore: number;
  private readonly rejectWithheld: boolean;
  private readonly denylist: Set<Did>;
  private readonly transientErrorPolicy: 'allow' | 'deny';

  constructor(
    private readonly client: MoltrustCaepClient,
    opts: GateOptions = {},
  ) {
    this.minScore = opts.minScore ?? 0;
    this.rejectWithheld = opts.rejectWithheld ?? true;
    this.denylist = opts.denylist ?? new Set();
    this.transientErrorPolicy = opts.transientErrorPolicy ?? 'deny';
    client.on('did_revoked', (did) => {
      this.denylist.add(did);
    });
  }

  /** Manually mark a DID as denied (e.g. operator action). */
  deny(did: Did): void {
    assertValidDid(did, 'EnforcementGate.deny');
    this.denylist.add(did);
  }

  /** Remove a DID from the denylist. */
  allowAgain(did: Did): void {
    assertValidDid(did, 'EnforcementGate.allowAgain');
    this.denylist.delete(did);
  }

  /** Returns the gate decision for a single DID. */
  async decide(did: Did): Promise<GateDecision> {
    assertValidDid(did, 'EnforcementGate.decide');
    if (this.denylist.has(did)) {
      return { allow: false, reason: 'denied_revoked', score: null };
    }
    let score: VerifiedTrustScore;
    try {
      score = await this.client.getVerifiedScore(did);
    } catch (err) {
      return this.errorDecision(err);
    }
    if (score.valid_until.getTime() < Date.now()) {
      return { allow: false, reason: 'denied_score_expired', score };
    }
    if (score.withheld && this.rejectWithheld) {
      return { allow: false, reason: 'denied_score_withheld', score };
    }
    if (score.trust_score === null || score.trust_score < this.minScore) {
      return { allow: false, reason: 'denied_score_below_threshold', score };
    }
    return { allow: true, reason: 'allowed', score };
  }

  private errorDecision(err: unknown): GateDecision {
    const code = err instanceof MoltrustFirewallError ? err.code : 'unknown';
    if (code === 'signature_invalid' || code === 'invalid_signature_encoding') {
      // Permanent error — the registry's response failed cryptographic
      // verification. Never fail-open on this regardless of policy.
      return { allow: false, reason: 'denied_signature_invalid', score: null, errorCode: code };
    }
    if (TRANSIENT_ERROR_CODES.has(code)) {
      const allow = this.transientErrorPolicy === 'allow';
      return {
        allow,
        reason: 'denied_transient_error',
        score: null,
        errorCode: code,
      };
    }
    return { allow: false, reason: 'denied_unknown_error', score: null, errorCode: code };
  }
}
