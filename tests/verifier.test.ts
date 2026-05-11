import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';

import { MoltrustVerifier } from '../src/verify/verifier.js';
import { RegistryKeyDiscovery } from '../src/verify/registry-key.js';
import { jcsCanonicalize } from '../src/verify/jcs.js';
import type { SignedTrustScoreResponse } from '../src/types.js';

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Builds a trust-score response shaped exactly like what api.moltrust.ch
 * emits today: bare base64url signature, signed over the 5-field minimal
 * payload (did, trust_score, computed_at, valid_until, policy_version).
 */
function signedScore(
  privateKey: Uint8Array,
  overrides: Partial<SignedTrustScoreResponse> = {},
): SignedTrustScoreResponse {
  const did = overrides.did ?? 'did:moltrust:abc1234567890def';
  const trust_score: number | null = 'trust_score' in overrides ? overrides.trust_score! : 82;
  const computed_at = overrides.computed_at ?? new Date(Date.now() - 60_000).toISOString();
  const valid_until = overrides.valid_until ?? new Date(Date.now() + 3_600_000).toISOString();
  const policy_version = overrides.evaluation_context?.policy_version ?? 'phase2';
  const signingPayload = { did, trust_score, computed_at, valid_until, policy_version };
  const sig = ed25519.sign(jcsCanonicalize(signingPayload), privateKey);
  return {
    did,
    trust_score,
    grade: overrides.grade ?? 'A',
    computed_at,
    valid_until,
    withheld: overrides.withheld ?? false,
    evaluation_context: {
      policy_version,
      evaluated_at: Math.floor(Date.now() / 1000) - 60,
      cache_valid_seconds: 3600,
    },
    registry_signature: base64UrlEncode(sig),
  };
}

function makeKeyDiscovery(publicKey: Uint8Array, kid: string): RegistryKeyDiscovery {
  const fetchImpl: typeof fetch = (async () =>
    new Response(
      JSON.stringify({
        kty: 'OKP',
        crv: 'Ed25519',
        x: base64UrlEncode(publicKey),
        kid,
        alg: 'EdDSA',
        use: 'sig',
      }),
      {
        status: 200,
        headers: { 'content-type': 'application/json', 'cache-control': 'max-age=3600' },
      },
    )) as typeof fetch;
  return new RegistryKeyDiscovery({ fetchImpl });
}

describe('MoltrustVerifier', () => {
  // Deterministic test key derived from a fixed 32-byte seed.
  const sk = new Uint8Array(32);
  for (let i = 0; i < 32; i++) sk[i] = i + 1; // 0x01..0x20
  const pk = ed25519.getPublicKey(sk);
  const kid = 'moltrust-registry-2026-v1';

  it('verifies a freshly-signed trust score', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk);
    const result = await verifier.verifyResponse(response);
    expect(result.did).toBe(response.did);
    expect(result.trust_score).toBe(82);
    expect(result.signed_by).toBe(kid);
    expect(result.policy_version).toBe('phase2');
  });

  it('verifies a withheld score (trust_score = null)', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk, { trust_score: null, withheld: true, grade: 'N/A' });
    const result = await verifier.verifyResponse(response);
    expect(result.trust_score).toBeNull();
    expect(result.withheld).toBe(true);
  });

  it('rejects a tampered score', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk);
    response.trust_score = 99; // tamper after signing
    await expect(verifier.verifyResponse(response)).rejects.toThrowError(/signature/);
  });

  it('rejects an expired score by default', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk, {
      valid_until: new Date(Date.now() - 1000).toISOString(),
    });
    await expect(verifier.verifyResponse(response)).rejects.toThrowError(/expired/);
  });

  it('returns expired scores when allowExpired is set', async () => {
    const verifier = new MoltrustVerifier({
      keyDiscovery: makeKeyDiscovery(pk, kid),
      allowExpired: true,
    });
    const response = signedScore(sk, {
      valid_until: new Date(Date.now() - 1000).toISOString(),
    });
    const result = await verifier.verifyResponse(response);
    expect(result.valid_until.getTime()).toBeLessThan(Date.now());
  });

  it('rejects a response missing evaluation_context.policy_version', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk);
    // Strip the required policy_version
    (response as unknown as { evaluation_context: Record<string, unknown> }).evaluation_context = {};
    await expect(verifier.verifyResponse(response)).rejects.toThrowError(/policy_version/);
  });

  it('rejects a signature that decodes to the wrong length', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk);
    response.registry_signature = 'AAAA'; // 3 bytes — far short of 64
    await expect(verifier.verifyResponse(response)).rejects.toThrowError(/64-byte/);
  });

  it('rejects non-string registry_signature', async () => {
    const verifier = new MoltrustVerifier({ keyDiscovery: makeKeyDiscovery(pk, kid) });
    const response = signedScore(sk);
    (response as unknown as { registry_signature: unknown }).registry_signature = {
      kid,
      alg: 'Ed25519',
      signature: 'xxx',
    };
    await expect(verifier.verifyResponse(response)).rejects.toThrowError(/base64url/);
  });
});
