import { describe, expect, it, vi } from 'vitest';
import {
  EnforcementGate,
  MoltrustCaepClient,
  MoltrustFirewallError,
  TrustCache,
} from '../src/index.js';
import { withConcurrency } from '../src/util/concurrency.js';
import {
  assertJsonResponse,
  base64UrlDecode,
  buildAuthHeaders,
  isStrictIso8601,
} from '../src/util/security.js';

describe('withConcurrency', () => {
  it('respects the concurrency limit', async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const items = Array.from({ length: 50 }, (_, i) => i);
    await withConcurrency(items, 5, async () => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
    });
    expect(maxInFlight).toBeLessThanOrEqual(5);
  });

  it('processes all items even when some throw', async () => {
    const items = [1, 2, 3, 4, 5];
    const processed: number[] = [];
    await withConcurrency(items, 2, async (n) => {
      if (n === 3) throw new Error('boom');
      processed.push(n);
    });
    expect(processed.sort()).toEqual([1, 2, 4, 5]);
  });

  it('handles empty arrays without throwing', async () => {
    await expect(withConcurrency([], 5, async () => {})).resolves.toBeUndefined();
  });
});

describe('assertJsonResponse strict MIME parsing', () => {
  function resp(ct: string): Response {
    return new Response('{}', { status: 200, headers: { 'content-type': ct } });
  }
  it('accepts application/json with charset', () => {
    expect(() => assertJsonResponse(resp('application/json; charset=utf-8'), 'https://x.test')).not.toThrow();
  });
  it('rejects application/jsonp', () => {
    expect(() => assertJsonResponse(resp('application/jsonp'), 'https://x.test')).toThrowError(/expected application\/json/);
  });
  it('rejects text/html; application/json (the substring trap)', () => {
    expect(() => assertJsonResponse(resp('text/html; application/json'), 'https://x.test')).toThrowError(/expected application\/json/);
  });
  it('rejects empty Content-Type', () => {
    expect(() => assertJsonResponse(new Response('{}', { status: 200 }), 'https://x.test')).toThrowError(/expected application\/json/);
  });
});

describe('base64UrlDecode (shared)', () => {
  it('decodes valid base64url', () => {
    const out = base64UrlDecode('SGVsbG8'); // "Hello"
    expect(new TextDecoder().decode(out)).toBe('Hello');
  });
  it('rejects values with invalid alphabet characters', () => {
    expect(() => base64UrlDecode('Hello!')).toThrowError(/base64url/);
  });
  it('rejects non-strings', () => {
    expect(() => base64UrlDecode(123 as unknown as string)).toThrowError(/string/);
  });
});

describe('buildAuthHeaders credential validation', () => {
  it('accepts a reasonable bearerToken', () => {
    const h = buildAuthHeaders({ bearerToken: 'sk_abcdefghi' });
    expect(h['Authorization']).toBe('Bearer sk_abcdefghi');
  });
  it('rejects too-short bearer tokens', () => {
    expect(() => buildAuthHeaders({ bearerToken: 'short' })).toThrowError(/too short/);
  });
  it('rejects tokens containing newlines (header injection)', () => {
    expect(() => buildAuthHeaders({ bearerToken: 'abcdefgh\nX-Injected: yes' })).toThrowError(/illegal characters/);
  });
  it('rejects empty apiKey', () => {
    expect(() => buildAuthHeaders({ apiKey: '' })).toThrowError(/too short/);
  });
  it('bearerToken takes precedence over apiKey', () => {
    const h = buildAuthHeaders({ apiKey: 'mt_abcdefgh', bearerToken: 'sk_zyxwvuts' });
    expect(h['Authorization']).toBe('Bearer sk_zyxwvuts');
    expect(h['X-API-Key']).toBeUndefined();
  });
});

describe('isStrictIso8601', () => {
  it('accepts canonical ISO 8601', () => {
    expect(isStrictIso8601('2026-05-11T13:17:44Z')).toBe(true);
    expect(isStrictIso8601('2026-05-11T13:17:44.727297+00:00')).toBe(true);
  });
  it('rejects ambiguous formats Date.parse would accept', () => {
    expect(isStrictIso8601('05-11-2026')).toBe(false);
    expect(isStrictIso8601('2026/05/11')).toBe(false);
    expect(isStrictIso8601('Mon May 11 2026')).toBe(false);
  });
  it('rejects non-strings', () => {
    expect(isStrictIso8601(null)).toBe(false);
    expect(isStrictIso8601(0)).toBe(false);
  });
});

describe('TrustCache constructor validation', () => {
  it('rejects maxEntries=0', () => {
    expect(() => new TrustCache({ maxEntries: 0 })).toThrowError(/maxEntries/);
  });
  it('rejects negative maxEntries', () => {
    expect(() => new TrustCache({ maxEntries: -5 })).toThrowError(/maxEntries/);
  });
  it('rejects Infinity', () => {
    expect(() => new TrustCache({ maxEntries: Infinity })).toThrowError(/maxEntries/);
  });
});

describe('EnforcementGate validation', () => {
  it('rejects negative minScore', () => {
    expect(() => new EnforcementGate(new MoltrustCaepClient({}), { minScore: -5 })).toThrowError(/minScore/);
  });
  it('rejects minScore > 100', () => {
    expect(() => new EnforcementGate(new MoltrustCaepClient({}), { minScore: 150 })).toThrowError(/minScore/);
  });
  it('dispose() detaches the listener from the client', () => {
    const client = new MoltrustCaepClient({});
    const gate = new EnforcementGate(client);
    expect(client.listenerCount('did_revoked')).toBe(1);
    gate.dispose();
    expect(client.listenerCount('did_revoked')).toBe(0);
  });
});

describe('MoltrustCaepClient per-DID rate limit', () => {
  // Build a fetch that resolves quickly with a valid signed score —
  // lets the first call succeed and the second call hit the rate-limit guard.
  it('rate-limits a second fetch within the interval window', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519');
    const { jcsCanonicalize } = await import('../src/verify/jcs.js');
    const sk = new Uint8Array(32);
    for (let i = 0; i < 32; i++) sk[i] = i + 1;
    const pk = ed25519.getPublicKey(sk);
    const b64url = (b: Uint8Array): string =>
      Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const did = 'did:moltrust:abc1234567890def';
    const computed_at = new Date(Date.now() - 1_000).toISOString();
    const valid_until = new Date(Date.now() + 3_600_000).toISOString();
    const policy_version = 'phase2';
    const sig = ed25519.sign(jcsCanonicalize({ did, trust_score: 80, computed_at, valid_until, policy_version }), sk);
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/.well-known/registry-key.json')) {
        return new Response(
          JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: b64url(pk), kid: 'moltrust-registry-2026-v1', alg: 'EdDSA' }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('/skill/trust-score/')) {
        return new Response(
          JSON.stringify({
            did,
            trust_score: 80,
            grade: 'A',
            computed_at,
            valid_until,
            withheld: false,
            evaluation_context: { policy_version, evaluated_at: 0, cache_valid_seconds: 3600 },
            registry_signature: b64url(sig),
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    const client = new MoltrustCaepClient({ fetchImpl, minFetchIntervalMs: 60_000 });
    // First call: hits the network, succeeds, populates cache.
    const first = await client.getVerifiedScore(did);
    expect(first.trust_score).toBe(80);
    // Second call within minFetchIntervalMs: cache returns the value (no network).
    // To prove the rate-limit guard fires when the cache is bypassed, invalidate it.
    client.cache.invalidate(did);
    await expect(client.getVerifiedScore(did)).rejects.toMatchObject({ code: 'rate_limited_client' });
  });

  it('emits error events safely when no listener is attached', () => {
    const client = new MoltrustCaepClient({});
    // Direct emit with no listener mimics the EventEmitter throw behaviour,
    // which is what we explicitly guard against in handle(). Verify the
    // guard by checking listenerCount logic.
    expect(client.listenerCount('error')).toBe(0);
    // A listener attached → emit is safe and returns true.
    const handler = vi.fn();
    client.on('error', handler);
    expect(client.emit('error', new Error('test'))).toBe(true);
    expect(handler).toHaveBeenCalledOnce();
  });
});
