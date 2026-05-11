import type { Did, VerifiedTrustScore } from '../types.js';
import type { MoltrustCaepClient } from '../caep/client.js';

export interface GateDecision {
  allow: boolean;
  /** Machine-readable reason — stable codes for telemetry. */
  reason:
    | 'allowed'
    | 'denied_score_below_threshold'
    | 'denied_score_withheld'
    | 'denied_score_expired'
    | 'denied_revoked'
    | 'denied_no_score';
  /** The verified score that informed the decision, if any. */
  score: VerifiedTrustScore | null;
}

export interface GateOptions {
  /** Minimum verified score required (0-100). Defaults to 0 (any score). */
  minScore?: number;
  /** Reject DIDs whose Phase 2 score is `withheld: true` (default true). */
  rejectWithheld?: boolean;
  /**
   * DIDs explicitly denied — typically populated by listening to
   * `client.on('did_revoked', ...)`. Pass your own Set if you want
   * to share state across gate instances.
   */
  denylist?: Set<Did>;
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

  constructor(
    private readonly client: MoltrustCaepClient,
    opts: GateOptions = {},
  ) {
    this.minScore = opts.minScore ?? 0;
    this.rejectWithheld = opts.rejectWithheld ?? true;
    this.denylist = opts.denylist ?? new Set();
    client.on('did_revoked', (did) => {
      this.denylist.add(did);
    });
  }

  /** Manually mark a DID as denied (e.g. operator action). */
  deny(did: Did): void {
    this.denylist.add(did);
  }

  /** Remove a DID from the denylist. */
  allowAgain(did: Did): void {
    this.denylist.delete(did);
  }

  /** Returns the gate decision for a single DID. */
  async decide(did: Did): Promise<GateDecision> {
    if (this.denylist.has(did)) {
      return { allow: false, reason: 'denied_revoked', score: null };
    }
    let score: VerifiedTrustScore;
    try {
      score = await this.client.getVerifiedScore(did);
    } catch {
      return { allow: false, reason: 'denied_no_score', score: null };
    }
    if (score.valid_until.getTime() < Date.now()) {
      return { allow: false, reason: 'denied_score_expired', score };
    }
    if (score.withheld && this.rejectWithheld) {
      return { allow: false, reason: 'denied_score_withheld', score };
    }
    if (score.score === null || score.score < this.minScore) {
      return { allow: false, reason: 'denied_score_below_threshold', score };
    }
    return { allow: true, reason: 'allowed', score };
  }
}
