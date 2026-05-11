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
   * Maximum number of DIDs the (default in-memory) denylist may hold.
   * When exceeded, the oldest-inserted entry is evicted FIFO. Defaults
   * to 100_000.
   *
   * Has NO effect when you pass your own `denylist` Set — that's
   * yours to manage. The cap only protects the default in-memory
   * implementation from unbounded growth on a stream of revocations.
   */
  maxDenylistSize?: number;
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
  private readonly maxDenylistSize: number;
  /**
   * Whether the gate owns its denylist (and may therefore enforce
   * the size cap). When the operator passes their own Set we treat
   * it as caller-managed and don't evict from it.
   */
  private readonly ownsDenylist: boolean;
  private readonly transientErrorPolicy: 'allow' | 'deny';
  /** Bound listener kept so `dispose()` can detach it cleanly. */
  private readonly onRevoked: (did: Did) => void;

  constructor(
    private readonly client: MoltrustCaepClient,
    opts: GateOptions = {},
  ) {
    const minScore = opts.minScore ?? 0;
    if (!Number.isFinite(minScore) || minScore < 0 || minScore > 100) {
      throw new MoltrustFirewallError(
        `minScore must be a finite number in 0..100 (got ${minScore})`,
        'invalid_min_score',
      );
    }
    this.minScore = minScore;
    this.rejectWithheld = opts.rejectWithheld ?? true;
    this.ownsDenylist = opts.denylist === undefined;
    this.denylist = opts.denylist ?? new Set();
    const cap = opts.maxDenylistSize ?? 100_000;
    if (!Number.isFinite(cap) || cap < 1) {
      throw new MoltrustFirewallError(
        `maxDenylistSize must be a finite integer >= 1 (got ${cap})`,
        'invalid_max_denylist_size',
      );
    }
    this.maxDenylistSize = cap;
    this.transientErrorPolicy = opts.transientErrorPolicy ?? 'deny';
    // NOTE: the client defaults to dropUnsignedEvents=true, which means
    // did_revoked typed handlers are not invoked unless the operator
    // explicitly opts in. In that case the auto-denylist below is dead
    // code — revocations still propagate, but only via the next signed
    // /skill/trust-score lookup. Document this trade-off so an operator
    // doesn't expect denylist auto-population in the default config.
    this.onRevoked = (did) => {
      this.addToDenylist(did);
    };
    client.on('did_revoked', this.onRevoked);
  }

  /**
   * Adds a DID to the denylist, evicting the oldest entry first if
   * the cap is reached. Only enforces the cap on the library-owned
   * default Set — caller-supplied Sets are mutated as-is and the
   * cap is the caller's concern.
   */
  private addToDenylist(did: Did): void {
    if (this.denylist.has(did)) return;
    if (this.ownsDenylist && this.denylist.size >= this.maxDenylistSize) {
      // Set preserves insertion order; the first entry is the oldest.
      const oldest = this.denylist.values().next().value;
      if (oldest !== undefined) this.denylist.delete(oldest);
    }
    this.denylist.add(did);
  }

  /**
   * Detaches the gate's listener from the client. Call this when the
   * gate's lifetime ends (e.g. a per-tenant middleware being torn
   * down). Otherwise the listener stays attached to the long-lived
   * client and the gate is kept alive by it — a memory leak in
   * dynamic / multi-tenant environments.
   */
  dispose(): void {
    this.client.off('did_revoked', this.onRevoked);
  }

  /** Manually mark a DID as denied (e.g. operator action). */
  deny(did: Did): void {
    assertValidDid(did, 'EnforcementGate.deny');
    this.addToDenylist(did);
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
