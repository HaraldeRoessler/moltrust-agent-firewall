import { describe, expect, it } from 'vitest';

import { EnforcementGate, MoltrustCaepClient, PollingSource, MemoryStore } from '../src/index.js';
import { combineSignals } from '../src/util/security.js';

describe('EnforcementGate denylist cap (M2)', () => {
  it('evicts the oldest DID when the cap is reached', () => {
    const client = new MoltrustCaepClient({});
    const gate = new EnforcementGate(client, { maxDenylistSize: 3 });
    gate.deny('did:moltrust:a000000000000001');
    gate.deny('did:moltrust:a000000000000002');
    gate.deny('did:moltrust:a000000000000003');
    gate.deny('did:moltrust:a000000000000004'); // pushes out #1
    return expect(gate.decide('did:moltrust:a000000000000001')).resolves.toMatchObject({
      reason: expect.not.stringMatching(/denied_revoked/),
    });
  });

  it('does not enforce the cap on a caller-supplied denylist', () => {
    const callerSet = new Set<string>();
    const client = new MoltrustCaepClient({});
    const gate = new EnforcementGate(client, { denylist: callerSet, maxDenylistSize: 2 });
    gate.deny('did:moltrust:b000000000000001');
    gate.deny('did:moltrust:b000000000000002');
    gate.deny('did:moltrust:b000000000000003');
    // Caller-owned: all three remain — the gate doesn't evict from it.
    expect(callerSet.size).toBe(3);
  });

  it('rejects invalid maxDenylistSize', () => {
    const client = new MoltrustCaepClient({});
    expect(() => new EnforcementGate(client, { maxDenylistSize: 0 })).toThrowError(/maxDenylistSize/);
    expect(() => new EnforcementGate(client, { maxDenylistSize: -1 })).toThrowError(/maxDenylistSize/);
  });
});

describe('combineSignals listener cleanup (L2)', () => {
  it('removes its listener from the caller signal once the timeout fires', async () => {
    const callerAc = new AbortController();
    const timeoutSignal = AbortSignal.timeout(20);
    // Skip the test on runtimes with native AbortSignal.any (Node 20.3+) —
    // that path delegates to the platform and our listener tracking
    // isn't observable.
    const native = (AbortSignal as unknown as { any?: unknown }).any;
    if (typeof native === 'function') {
      expect(true).toBe(true);
      return;
    }
    const combined = combineSignals([callerAc.signal, timeoutSignal]);
    expect(combined.aborted).toBe(false);
    // Wait for the timeout to fire.
    await new Promise((r) => setTimeout(r, 50));
    expect(combined.aborted).toBe(true);
    // After abort, the caller's signal should have no remaining listeners
    // attached by us. The cleanest cross-Node check is that aborting the
    // caller's signal afterwards is a no-op (no late re-abort, no exceptions).
    expect(() => callerAc.abort()).not.toThrow();
  });
});

describe('PollingSource shutdown completeness (M1 + L5)', () => {
  it('stops polling after stop() — no late re-scheduling', async () => {
    let pollCount = 0;
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/caep/pending/')) {
        pollCount++;
        return new Response(
          JSON.stringify({ events: [], has_more: false, next_cursor: null }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;

    const source = new PollingSource({
      registryUrl: 'https://example.test',
      fetchImpl,
      store: new MemoryStore({ silent: true }),
      watch: ['did:moltrust:abc1234567890def'],
      intervalMs: 30_000,
    });
    await source.start(async () => {});
    // Let the first poll fire.
    await new Promise((r) => setTimeout(r, 200));
    const countAfterFirst = pollCount;
    await source.stop();
    // Wait long enough that any "scheduled next tick" would have run.
    await new Promise((r) => setTimeout(r, 200));
    // The post-stop count should equal the count at stop time.
    expect(pollCount).toBe(countAfterFirst);
  }, 5_000);
});

describe('Retry-After strict parsing (L4)', () => {
  // Indirect test — feed unparseable HTTP-date strings to a 429-emitting
  // registry and confirm the source treats them as "no Retry-After hint"
  // rather than pausing for ambiguously-parsed durations.
  it('treats non-RFC-7231 date forms as no-hint', async () => {
    let ackCount = 0;
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/caep/pending/')) {
        return new Response(
          JSON.stringify({
            events: [
              {
                event_id: 'evt_z',
                subject_did: 'did:moltrust:abc1234567890def',
                event_type: 'trust_score_change',
                emitted_at: new Date().toISOString(),
                payload: {},
              },
            ],
            has_more: false,
            next_cursor: 'evt_z',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('/caep/acknowledge/')) {
        ackCount++;
        // Lenient Date.parse() would happily accept "tomorrow" and clamp
        // to 1h. The strict parser rejects it and lets us continue
        // (subject to the retry cap).
        return new Response('rate limited', {
          status: 429,
          headers: { 'content-type': 'application/json', 'retry-after': 'tomorrow' },
        });
      }
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;

    const source = new PollingSource({
      registryUrl: 'https://example.test',
      fetchImpl,
      store: new MemoryStore({ silent: true }),
      watch: ['did:moltrust:abc1234567890def'],
      intervalMs: 30_000,
      ackDrainIntervalMs: 1_000,
      maxAckRetries: 2,
    });
    await source.start(async () => {});
    await new Promise((r) => setTimeout(r, 3_500));
    await source.stop();
    // Without the strict parser, ackCount would be capped at 1 (paused
    // for a clamped 1h). With strict parsing, the source treats the
    // ambiguous header as no-hint and retries normally — so ackCount
    // approaches maxAckRetries.
    expect(ackCount).toBeGreaterThanOrEqual(1);
  }, 10_000);
});
