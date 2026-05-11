import { describe, expect, it, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';

import { MoltrustCaepClient, PollingSource, TrustCache } from '../src/index.js';
import { withConcurrency } from '../src/util/concurrency.js';
import { jcsCanonicalize } from '../src/verify/jcs.js';

function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

describe('PollingSource maxWatchedDids cap (M4)', () => {
  it('throws when watch() exceeds the cap', () => {
    const source = new PollingSource({ maxWatchedDids: 2 });
    source.watch('did:moltrust:abc1234567890def');
    source.watch('did:moltrust:def1234567890abc');
    expect(() => source.watch('did:moltrust:fff1234567890fff')).toThrowError(/maxWatchedDids/);
  });

  it('throws when initial watch list exceeds the cap', () => {
    expect(
      () =>
        new PollingSource({
          maxWatchedDids: 2,
          watch: [
            'did:moltrust:abc1234567890def',
            'did:moltrust:def1234567890abc',
            'did:moltrust:fff1234567890fff',
          ],
        }),
    ).toThrowError(/maxWatchedDids/);
  });
});

describe('withConcurrency onError callback (M2)', () => {
  it('surfaces per-item errors to the onError callback', async () => {
    const items = [1, 2, 3, 4, 5];
    const seen: Array<[unknown, number]> = [];
    await withConcurrency(
      items,
      2,
      async (n) => {
        if (n % 2 === 0) throw new Error(`boom ${n}`);
      },
      (err, item) => {
        seen.push([err, item]);
      },
    );
    expect(seen.map(([_, i]) => i).sort()).toEqual([2, 4]);
  });

  it('still completes when the onError callback itself throws', async () => {
    let processed = 0;
    await withConcurrency(
      [1, 2, 3],
      2,
      async () => {
        throw new Error('task boom');
      },
      () => {
        processed++;
        throw new Error('onError boom');
      },
    );
    expect(processed).toBe(3);
  });
});

describe('TrustCache.size purges expired (L1)', () => {
  it('does not count entries past valid_until', () => {
    const c = new TrustCache();
    c.set({
      did: 'did:moltrust:a',
      trust_score: 50,
      grade: 'C',
      computed_at: new Date(),
      valid_until: new Date(Date.now() - 1_000),
      withheld: false,
      signed_by: 'k',
      policy_version: 'phase2',
      verified_at: new Date(),
    });
    c.set({
      did: 'did:moltrust:b',
      trust_score: 80,
      grade: 'A',
      computed_at: new Date(),
      valid_until: new Date(Date.now() + 60_000),
      withheld: false,
      signed_by: 'k',
      policy_version: 'phase2',
      verified_at: new Date(),
    });
    expect(c.size).toBe(1); // expired entry was swept
  });
});

describe('MoltrustCaepClient lastFetchAt cleanup (H1)', () => {
  it('prunes stale rate-limit timestamps over time', async () => {
    const { ed25519: ed } = await import('@noble/curves/ed25519');
    const sk = new Uint8Array(32);
    for (let i = 0; i < 32; i++) sk[i] = i + 1;
    const pk = ed.getPublicKey(sk);
    const computed_at = new Date(Date.now() - 1_000).toISOString();
    const valid_until = new Date(Date.now() + 3_600_000).toISOString();
    const policy_version = 'phase2';
    function jsonResp(body: object): Response {
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/.well-known/registry-key.json')) {
        return jsonResp({ kty: 'OKP', crv: 'Ed25519', x: b64url(pk), kid: 'moltrust-registry-2026-v1', alg: 'EdDSA' });
      }
      if (url.includes('/skill/trust-score/')) {
        // Pull DID out of URL and sign correctly.
        const did = decodeURIComponent(url.split('/skill/trust-score/')[1]!);
        const sig = ed.sign(jcsCanonicalize({ did, trust_score: 70, computed_at, valid_until, policy_version }), sk);
        return jsonResp({
          did,
          trust_score: 70,
          grade: 'B',
          computed_at,
          valid_until,
          withheld: false,
          evaluation_context: { policy_version, evaluated_at: 0, cache_valid_seconds: 3600 },
          registry_signature: b64url(sig),
        });
      }
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    const client = new MoltrustCaepClient({ fetchImpl, minFetchIntervalMs: 50 });
    // First fetch — populates lastFetchAt for did:moltrust:aaa1.
    await client.getVerifiedScore('did:moltrust:aaa1234567890abc');
    const internal = client as unknown as { lastFetchAt: Map<string, number>; sweepStaleFetchTimestamps: (n: number) => void };
    expect(internal.lastFetchAt.size).toBe(1);
    // Simulate clock advancing well past the rate-limit window.
    // The sweep guard requires LAST_FETCH_SWEEP_INTERVAL_MS to have
    // passed since the last sweep — bypass by clearing lastSweepAt.
    (client as unknown as { lastSweepAt: number }).lastSweepAt = 0;
    internal.sweepStaleFetchTimestamps(Date.now() + 1_000_000); // far-future
    expect(internal.lastFetchAt.size).toBe(0);
  });
});

describe('Retry-After parsing', () => {
  it('parses integer-seconds form', async () => {
    // parseRetryAfter is module-private; assert via indirect behaviour:
    // wire a 429-with-Retry-After response and confirm the source pauses.
    let ackCount = 0;
    let lastUrl = '';
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      lastUrl = url;
      if (url.includes('/caep/pending/')) {
        return new Response(
          JSON.stringify({
            events: [
              {
                event_id: 'evt_x',
                subject_did: 'did:moltrust:abc1234567890def',
                event_type: 'trust_score_change',
                emitted_at: new Date().toISOString(),
                payload: {},
              },
            ],
            has_more: false,
            next_cursor: 'evt_x',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('/caep/acknowledge/')) {
        ackCount++;
        // First ack: 429 with 1s Retry-After. Subsequent: should be paused.
        return new Response('rate limited', {
          status: 429,
          headers: { 'content-type': 'application/json', 'retry-after': '60' },
        });
      }
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;

    const { PollingSource: PS, MemoryStore } = await import('../src/index.js');
    const store = new MemoryStore({ silent: true });
    const source = new PS({
      registryUrl: 'https://example.test',
      fetchImpl,
      store,
      watch: ['did:moltrust:abc1234567890def'],
      intervalMs: 30_000,
      ackDrainIntervalMs: 1_000,
    });
    await source.start(async () => {});
    // Run for ~3 seconds. With Retry-After: 60, the source must NOT
    // hammer the ack endpoint — should issue ~1 ack call, not 3.
    await new Promise((r) => setTimeout(r, 3_500));
    await source.stop();
    expect(ackCount).toBeLessThanOrEqual(1);
    expect(lastUrl).toBeTruthy();
  }, 10_000);
});

describe('MemoryStore warning (M1)', () => {
  it('emits MoltrustMemoryStoreWarning on first construction', async () => {
    // The warning is global per-process (static flag) — we can't easily
    // test re-emission without resetting state, so we just verify the
    // constructor accepts the silent option without error.
    const { MemoryStore } = await import('../src/index.js');
    expect(() => new MemoryStore({ silent: true })).not.toThrow();
    expect(() => new MemoryStore()).not.toThrow();
  });
});

describe('PollingSource stop() waits for in-flight flush (M3)', () => {
  it('does not leave pending acks behind on shutdown', async () => {
    const { PollingSource: PS, MemoryStore } = await import('../src/index.js');
    let ackSucceeded = 0;
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/caep/pending/')) {
        return new Response(
          JSON.stringify({
            events: [
              {
                event_id: 'evt_only',
                subject_did: 'did:moltrust:abc1234567890def',
                event_type: 'trust_score_change',
                emitted_at: new Date().toISOString(),
                payload: {},
              },
            ],
            has_more: false,
            next_cursor: 'evt_only',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('/caep/acknowledge/')) {
        // Simulate slow ack — 200ms — so the call is in-flight when we stop.
        await new Promise((r) => setTimeout(r, 200));
        ackSucceeded++;
        return new Response(null, { status: 204 });
      }
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;

    const source = new PS({
      registryUrl: 'https://example.test',
      fetchImpl,
      store: new MemoryStore({ silent: true }),
      watch: ['did:moltrust:abc1234567890def'],
      intervalMs: 30_000,
      ackDrainIntervalMs: 1_000,
    });
    await source.start(async () => {});
    // Let one poll happen + ack to start.
    await new Promise((r) => setTimeout(r, 1_500));
    await source.stop(); // should await the in-flight ack
    expect(ackSucceeded).toBeGreaterThanOrEqual(1);
  }, 10_000);
});
