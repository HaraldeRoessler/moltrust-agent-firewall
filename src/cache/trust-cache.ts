import { MoltrustFirewallError, type Did, type VerifiedTrustScore } from '../types.js';

/**
 * In-memory cache of verified trust scores keyed by DID.
 *
 * - Entries respect their own `valid_until` — `get` returns null
 *   once the cached score has expired.
 * - A separate LRU-style soft cap (`maxEntries`) prevents unbounded
 *   growth in firewalls watching many DIDs.
 * - `invalidate(did)` is called by the CAEP client on
 *   `trust_score_change` / `did_revoked` events so a stale cache
 *   never outlives a registry update.
 */
export interface TrustCacheOptions {
  maxEntries?: number;
  now?: () => number;
}

export class TrustCache {
  private readonly entries = new Map<Did, VerifiedTrustScore>();
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(opts: TrustCacheOptions = {}) {
    const maxEntries = opts.maxEntries ?? 10_000;
    if (!Number.isFinite(maxEntries) || maxEntries < 1) {
      throw new MoltrustFirewallError(
        `maxEntries must be a finite integer >= 1 (got ${maxEntries})`,
        'invalid_max_entries',
      );
    }
    this.maxEntries = maxEntries;
    this.now = opts.now ?? (() => Date.now());
  }

  /** Returns the cached verified score for `did`, or null if absent/expired. */
  get(did: Did): VerifiedTrustScore | null {
    const e = this.entries.get(did);
    if (!e) return null;
    if (e.valid_until.getTime() < this.now()) {
      this.entries.delete(did);
      return null;
    }
    // bump LRU recency
    this.entries.delete(did);
    this.entries.set(did, e);
    return e;
  }

  set(score: VerifiedTrustScore): void {
    if (this.entries.has(score.did)) {
      this.entries.delete(score.did);
    } else if (this.entries.size >= this.maxEntries) {
      // evict oldest (first inserted) — Map preserves insertion order
      const firstKey = this.entries.keys().next().value;
      if (firstKey !== undefined) this.entries.delete(firstKey);
    }
    this.entries.set(score.did, score);
  }

  invalidate(did: Did): void {
    this.entries.delete(did);
  }

  /**
   * Returns the number of live (non-expired) entries.
   *
   * Sweeps expired entries while counting so metrics built from
   * this getter never overcount stale ones. The cost is O(n) on
   * call; cache implementations needing constant-time `size` can
   * use the in-memory Map directly via composition.
   */
  get size(): number {
    const now = this.now();
    for (const [did, e] of this.entries) {
      if (e.valid_until.getTime() < now) this.entries.delete(did);
    }
    return this.entries.size;
  }

  clear(): void {
    this.entries.clear();
  }
}
