import { describe, expect, it, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';

import {
  MoltrustCaepClient,
  type CaepEvent,
  type PollingSourceOptions,
} from '../src/index.js';
import { jcsCanonicalize } from '../src/verify/jcs.js';

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

const TEST_SK = new Uint8Array(32);
for (let i = 0; i < 32; i++) TEST_SK[i] = i + 1;
const TEST_PK = ed25519.getPublicKey(TEST_SK);
const KID = 'moltrust-registry-2026-v1';

function jwkResponse(): Response {
  return new Response(
    JSON.stringify({
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64UrlEncode(TEST_PK),
      kid: KID,
      alg: 'EdDSA',
    }),
    { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'max-age=3600' } },
  );
}

function signedScoreResponse(did: string, score: number): Response {
  const body = {
    did,
    score,
    grade: 'A',
    computed_at: new Date(Date.now() - 1_000).toISOString(),
    valid_until: new Date(Date.now() + 3_600_000).toISOString(),
    withheld: false,
  };
  const sig = ed25519.sign(jcsCanonicalize(body), TEST_SK);
  return new Response(
    JSON.stringify({
      ...body,
      registry_signature: { kid: KID, alg: 'Ed25519', signature: hexEncode(sig) },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

describe('MoltrustCaepClient', () => {
  it('singleflights concurrent getVerifiedScore calls for the same DID', async () => {
    const calls: string[] = [];
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      calls.push(url);
      if (url.includes('/.well-known/registry-key.json')) return jwkResponse();
      if (url.includes('/skill/trust-score/')) return signedScoreResponse('did:moltrust:abc', 75);
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;

    const client = new MoltrustCaepClient({ fetchImpl });
    const did = 'did:moltrust:abc';
    const results = await Promise.all([
      client.getVerifiedScore(did),
      client.getVerifiedScore(did),
      client.getVerifiedScore(did),
      client.getVerifiedScore(did),
    ]);

    expect(results.every((r) => r.score === 75)).toBe(true);
    const scoreFetches = calls.filter((u) => u.includes('/skill/trust-score/'));
    expect(scoreFetches.length).toBe(1); // singleflight collapsed the four concurrent calls
  });

  it('defaults dropUnsignedEvents to true (typed did_revoked handler not invoked)', async () => {
    const event: CaepEvent = {
      event_id: 'evt_1',
      subject_did: 'did:moltrust:abc',
      event_type: 'did_revoked',
      emitted_at: new Date().toISOString(),
      payload: { reason: 'manual', revoked_at: new Date().toISOString() },
    };
    let respondedOnce = false;
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/caep/pending/')) {
        if (respondedOnce) {
          return new Response(JSON.stringify({ events: [], has_more: false, next_cursor: null }), {
            status: 200, headers: { 'content-type': 'application/json' },
          });
        }
        respondedOnce = true;
        return new Response(JSON.stringify({ events: [event], has_more: false, next_cursor: 'evt_1' }), {
          status: 200, headers: { 'content-type': 'application/json' },
        });
      }
      if (url.includes('/caep/acknowledge/')) return new Response(null, { status: 204 });
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;

    const typedHandler = vi.fn();
    const genericHandler = vi.fn();
    const polling: PollingSourceOptions = { watch: ['did:moltrust:abc'], intervalMs: 30_000 };
    const client = new MoltrustCaepClient({ fetchImpl, polling });
    client.on('did_revoked', typedHandler);
    client.on('event', genericHandler);

    await client.start();
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    await client.stop();

    expect(typedHandler).not.toHaveBeenCalled();
    expect(genericHandler).toHaveBeenCalledTimes(1);
  }, 10_000);

  it('emits typed did_revoked when dropUnsignedEvents=false (with a warning)', async () => {
    const event: CaepEvent = {
      event_id: 'evt_2',
      subject_did: 'did:moltrust:abc',
      event_type: 'did_revoked',
      emitted_at: new Date().toISOString(),
      payload: { revoked_at: new Date().toISOString() },
    };
    let respondedOnce = false;
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/caep/pending/')) {
        if (respondedOnce) {
          return new Response(JSON.stringify({ events: [], has_more: false, next_cursor: null }), {
            status: 200, headers: { 'content-type': 'application/json' },
          });
        }
        respondedOnce = true;
        return new Response(JSON.stringify({ events: [event], has_more: false, next_cursor: 'evt_2' }), {
          status: 200, headers: { 'content-type': 'application/json' },
        });
      }
      if (url.includes('/caep/acknowledge/')) return new Response(null, { status: 204 });
      return new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;

    const typedHandler = vi.fn();
    const polling: PollingSourceOptions = { watch: ['did:moltrust:abc'], intervalMs: 30_000 };
    const client = new MoltrustCaepClient({ fetchImpl, polling, dropUnsignedEvents: false });
    client.on('did_revoked', typedHandler);

    await client.start();
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    await client.stop();

    expect(typedHandler).toHaveBeenCalledTimes(1);
  }, 10_000);
});
