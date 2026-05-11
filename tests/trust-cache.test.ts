import { describe, expect, it } from 'vitest';
import { TrustCache } from '../src/cache/trust-cache.js';
import type { VerifiedTrustScore } from '../src/types.js';

function score(did: string, validUntil: Date, value = 70): VerifiedTrustScore {
  return {
    did,
    trust_score: value,
    grade: 'B',
    computed_at: new Date(Date.now() - 1000),
    valid_until: validUntil,
    withheld: false,
    signed_by: 'moltrust-registry-2026-v1',
    policy_version: 'phase2',
    verified_at: new Date(),
  };
}

describe('TrustCache', () => {
  it('returns null for a missing DID', () => {
    expect(new TrustCache().get('did:moltrust:nope')).toBeNull();
  });

  it('returns the cached score within valid_until', () => {
    const c = new TrustCache();
    const s = score('did:moltrust:a', new Date(Date.now() + 60_000));
    c.set(s);
    expect(c.get('did:moltrust:a')?.trust_score).toBe(70);
  });

  it('evicts entries past valid_until on read', () => {
    const c = new TrustCache();
    c.set(score('did:moltrust:expired', new Date(Date.now() - 1)));
    expect(c.get('did:moltrust:expired')).toBeNull();
    expect(c.size).toBe(0);
  });

  it('invalidate() removes the entry immediately', () => {
    const c = new TrustCache();
    c.set(score('did:moltrust:a', new Date(Date.now() + 60_000)));
    c.invalidate('did:moltrust:a');
    expect(c.get('did:moltrust:a')).toBeNull();
  });

  it('evicts the oldest entry when maxEntries is exceeded', () => {
    const c = new TrustCache({ maxEntries: 2 });
    c.set(score('a', new Date(Date.now() + 60_000)));
    c.set(score('b', new Date(Date.now() + 60_000)));
    c.set(score('c', new Date(Date.now() + 60_000)));
    expect(c.get('a')).toBeNull();
    expect(c.get('b')?.did).toBe('b');
    expect(c.get('c')?.did).toBe('c');
  });
});
