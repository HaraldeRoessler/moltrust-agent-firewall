import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';

import { MoltrustVerifier } from '../src/verify/verifier.js';
import { RegistryKeyDiscovery } from '../src/verify/registry-key.js';
import { jcsCanonicalize } from '../src/verify/jcs.js';
import type { SignedTrustScoreResponse } from '../src/types.js';

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function signedScore(privateKey: Uint8Array, kid: string, overrides: Partial<SignedTrustScoreResponse> = {}): SignedTrustScoreResponse {
  const base = {
    did: 'did:moltrust:abc123',
    score: 82,
    grade: 'A',
    computed_at: new Date(Date.now() - 60_000).toISOString(),
    valid_until: new Date(Date.now() + 3600_000).toISOString(),
    withheld: false,
    ...overrides,
  } as Omit<SignedTrustScoreResponse, 'registry_signature'>;
  const sig = ed25519.sign(jcsCanonicalize(base), privateKey);
  return {
    ...base,
    registry_signature: {
      kid,
      alg: 'Ed25519',
      signature: hexEncode(sig),
    },
  };
}

function makeKeyDiscovery(publicKey: Uint8Array, kid: string): RegistryKeyDiscovery {
  const fetchImpl: typeof fetch = (async () =>
    new Response(
      JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: base64UrlEncode(publicKey), kid, alg: 'EdDSA', use: 'sig' }),
      { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'max-age=3600' } },
    )) as typeof fetch;
  return new RegistryKeyDiscovery({ fetchImpl });
}

describe('MoltrustVerifier', () => {
  // Deterministic test key derived from a fixed 32-byte seed. Using a
  // pinned secret makes intermittent test failures reproducible and lets
  // signature regressions surface as exact-bytes diffs in CI.
  const sk = new Uint8Array(32);
  for (let i = 0; i < 32; i++) sk[i] = i + 1; // 0x01..0x20
  const pk = ed25519.getPublicKey(sk);
  const kid = 'moltrust-registry-2026-v1';

  it('verifies a freshly-signed trust score', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk, kid);
    const result = await verifier.verifyResponse(response);
    expect(result.did).toBe(response.did);
    expect(result.score).toBe(82);
    expect(result.signed_by).toBe(kid);
  });

  it('rejects a tampered score', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk, kid);
    response.score = 99; // tamper after signing
    await expect(verifier.verifyResponse(response)).rejects.toThrowError(/signature/);
  });

  it('rejects an expired score by default', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk, kid, {
      valid_until: new Date(Date.now() - 1000).toISOString(),
    });
    await expect(verifier.verifyResponse(response)).rejects.toThrowError(/expired/);
  });

  it('returns expired scores when allowExpired is set', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid), allowExpired: true });
    const response = signedScore(sk, kid, {
      valid_until: new Date(Date.now() - 1000).toISOString(),
    });
    const result = await verifier.verifyResponse(response);
    expect(result.valid_until.getTime()).toBeLessThan(Date.now());
  });

  it('rejects an unknown signature algorithm', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk, kid);
    response.registry_signature.alg = 'RS256' as 'Ed25519';
    await expect(verifier.verifyResponse(response)).rejects.toThrowError(/Ed25519/);
  });

  it('rejects a signature from an unknown kid', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk, 'rotated-kid-that-registry-doesnt-publish');
    await expect(verifier.verifyResponse(response)).rejects.toThrowError(/kid/);
  });
});
