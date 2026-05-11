import { ed25519 } from '@noble/curves/ed25519';

import {
  DEFAULT_REGISTRY,
  MoltrustFirewallError,
  type Did,
  type SignedTrustScoreResponse,
  type VerifiedTrustScore,
} from '../types.js';
import { RegistryKeyDiscovery, type RegistryKeyDiscoveryOptions } from './registry-key.js';
import { trustScoreSigningInput } from './jcs.js';
import {
  assertJsonResponse,
  assertValidDid,
  buildAuthHeaders,
  fetchWithTimeout,
  readJsonBoundedBody,
  validateRegistryUrl,
} from '../util/security.js';

const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

export interface VerifierOptions extends RegistryKeyDiscoveryOptions {
  registryUrl?: string;
  fetchImpl?: typeof fetch;
  keyDiscovery?: RegistryKeyDiscovery;
  /**
   * Allow trust scores whose `valid_until` is in the past, returning them with
   * `expired: true` rather than throwing. Defaults to false (strict).
   */
  allowExpired?: boolean;
  /** Per-request HTTP timeout in ms (default 10s). */
  requestTimeoutMs?: number;
  /** Optional API key sent as `X-API-Key`. Prefer `bearerToken`. */
  apiKey?: string;
  /** Optional bearer token sent as `Authorization: Bearer ...` (preferred). */
  bearerToken?: string;
  /** Never set in production. See RegistryKeyDiscoveryOptions. */
  dangerouslyAllowHttp?: boolean;
}

/**
 * Fetches and verifies signed trust-score responses from the MolTrust
 * registry.
 *
 * Verification semantics:
 *
 * 1. The response is read from GET /skill/trust-score/{did} (or fed in
 *    directly via `verifyResponse`).
 * 2. The `kid` in `registry_signature` is looked up via
 *    GET /.well-known/registry-key.json (cached).
 * 3. The signing input is the RFC 8785 (JCS) canonicalisation of the
 *    response with the `registry_signature` field stripped.
 * 4. The Ed25519 signature is verified using @noble/curves.
 * 5. `valid_until` is checked against the local clock; expired
 *    responses are rejected unless `allowExpired: true` is set.
 */
export class MoltrustVerifier {
  private readonly registryUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly keyDiscovery: RegistryKeyDiscovery;
  private readonly allowExpired: boolean;
  private readonly requestTimeoutMs: number;
  private readonly authHeaders: Record<string, string>;

  constructor(opts: VerifierOptions = {}) {
    this.registryUrl = validateRegistryUrl(
      opts.registryUrl ?? DEFAULT_REGISTRY,
      opts.dangerouslyAllowHttp ?? false,
    );
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.allowExpired = opts.allowExpired ?? false;
    if (this.allowExpired) {
      process.emitWarning(
        'MoltrustVerifier created with allowExpired=true. Expired trust ' +
          'scores will be accepted as valid — typical only for graceful ' +
          'degradation during a registry outage. NEVER use as a normal ' +
          'production setting.',
        'MoltrustExpiredScoresWarning',
      );
    }
    this.requestTimeoutMs = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    const authOpts: { apiKey?: string; bearerToken?: string } = {};
    if (opts.apiKey !== undefined) authOpts.apiKey = opts.apiKey;
    if (opts.bearerToken !== undefined) authOpts.bearerToken = opts.bearerToken;
    this.authHeaders = buildAuthHeaders(authOpts);
    this.keyDiscovery =
      opts.keyDiscovery ??
      new RegistryKeyDiscovery({
        registryUrl: this.registryUrl,
        fetchImpl: this.fetchImpl,
        requestTimeoutMs: this.requestTimeoutMs,
        dangerouslyAllowHttp: opts.dangerouslyAllowHttp ?? false,
        ...(opts.maxCacheTtlMs !== undefined ? { maxCacheTtlMs: opts.maxCacheTtlMs } : {}),
      });
  }

  /** Convenience: fetch + verify a trust score for a DID. */
  async fetchAndVerify(did: Did): Promise<VerifiedTrustScore> {
    assertValidDid(did, 'fetchAndVerify');
    const url = `${this.registryUrl}/skill/trust-score/${encodeURIComponent(did)}`;
    let response: Response;
    try {
      response = await fetchWithTimeout(
        this.fetchImpl,
        url,
        { method: 'GET', headers: { Accept: 'application/json', ...this.authHeaders } },
        this.requestTimeoutMs,
      );
    } catch (err) {
      if (err instanceof MoltrustFirewallError) throw err;
      // DID is included because it's a public-by-design identifier
      // (mirroring the moltrust.ch /verify/<did> public page); the
      // raw URL is intentionally not — see sanitiseUrl in
      // src/util/security.ts for rationale.
      throw new MoltrustFirewallError(
        `failed to fetch trust score for ${did}`,
        'fetch_failed',
        err,
      );
    }
    if (!response.ok) {
      throw new MoltrustFirewallError(
        `trust score endpoint returned HTTP ${response.status}`,
        'http_error',
      );
    }
    assertJsonResponse(response, url);
    const body = await readJsonBoundedBody<SignedTrustScoreResponse>(response, url);
    return this.verifyResponse(body);
  }

  /** Verify a trust-score response payload (already fetched). */
  async verifyResponse(response: SignedTrustScoreResponse): Promise<VerifiedTrustScore> {
    if (!response.registry_signature) {
      throw new MoltrustFirewallError(
        'response is missing registry_signature',
        'missing_signature',
      );
    }
    if (response.registry_signature.alg !== 'Ed25519') {
      throw new MoltrustFirewallError(
        `unsupported signature alg '${response.registry_signature.alg}' (only Ed25519 supported in v1)`,
        'unsupported_alg',
      );
    }
    const key = await this.keyDiscovery.getKey(response.registry_signature.kid);
    const signingInput = trustScoreSigningInput(response as unknown as Record<string, unknown>);
    const signatureBytes = hexDecode(response.registry_signature.signature);

    let ok: boolean;
    try {
      ok = ed25519.verify(signatureBytes, signingInput, key.publicKey);
    } catch (err) {
      throw new MoltrustFirewallError(
        'Ed25519 signature verification threw',
        'signature_invalid',
        err,
      );
    }
    if (!ok) {
      throw new MoltrustFirewallError(
        'Ed25519 signature did not verify against published registry key',
        'signature_invalid',
      );
    }

    const validUntil = new Date(response.valid_until);
    if (Number.isNaN(validUntil.getTime())) {
      throw new MoltrustFirewallError(
        `valid_until is not a valid ISO 8601 timestamp: ${response.valid_until}`,
        'invalid_valid_until',
      );
    }
    if (!this.allowExpired && validUntil.getTime() < Date.now()) {
      throw new MoltrustFirewallError(
        `trust score for ${response.did} expired at ${response.valid_until}`,
        'score_expired',
      );
    }

    const computedAt = new Date(response.computed_at);
    if (Number.isNaN(computedAt.getTime())) {
      throw new MoltrustFirewallError(
        `computed_at is not a valid ISO 8601 timestamp: ${response.computed_at}`,
        'invalid_computed_at',
      );
    }

    return {
      did: response.did,
      score: response.score,
      grade: response.grade,
      computed_at: computedAt,
      valid_until: validUntil,
      withheld: response.withheld,
      signed_by: response.registry_signature.kid,
      verified_at: new Date(),
    };
  }

  /** Expose the underlying key discovery (e.g. for diagnostic logging). */
  get keys(): RegistryKeyDiscovery {
    return this.keyDiscovery;
  }
}

function hexDecode(s: string): Uint8Array {
  if (s.length % 2 !== 0) {
    throw new MoltrustFirewallError(
      `signature hex string has odd length (${s.length})`,
      'invalid_signature_encoding',
    );
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new MoltrustFirewallError(
        `signature is not valid hex at offset ${i * 2}`,
        'invalid_signature_encoding',
      );
    }
    out[i] = byte;
  }
  return out;
}
