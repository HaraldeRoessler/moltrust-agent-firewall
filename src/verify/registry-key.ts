import {
  DEFAULT_KID,
  DEFAULT_REGISTRY,
  MoltrustFirewallError,
  type JsonWebKey,
  type RegistryKey,
} from '../types.js';
import {
  assertJsonResponse,
  base64UrlDecode,
  defaultRequestHeaders,
  fetchWithTimeout,
  readJsonBoundedBody,
  validateRegistryUrl,
} from '../util/security.js';

const MIN_CACHE_TTL_MS = 60_000; // never honour Cache-Control below 60s
const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000; // 1h fallback
const MAX_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // hard ceiling: 24h
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

export interface RegistryKeyDiscoveryOptions {
  registryUrl?: string;
  fetchImpl?: typeof fetch;
  /** Override the cache TTL ceiling (defaults to 24h). */
  maxCacheTtlMs?: number;
  /** Per-request HTTP timeout in ms (default 10s). */
  requestTimeoutMs?: number;
  /**
   * Allow `http://` registry URLs. NEVER set this in production —
   * cleartext HTTP would expose DIDs, scores, and any API key in
   * transit. The flag exists only for local development against
   * a mocked registry.
   */
  dangerouslyAllowHttp?: boolean;
}

/**
 * Fetches and caches the registry's Ed25519 signing key from
 * GET /.well-known/registry-key.json.
 *
 * Caching honours the response `Cache-Control: max-age=` directive,
 * clamped to [60s, 24h]. The library also caches by `kid`, so when
 * the registry rotates keys mid-cache, both the previous and the
 * new key remain resolvable until the previous entry expires (a
 * small grace window that lets in-flight verifications complete
 * during a rotation).
 */
export class RegistryKeyDiscovery {
  private byKid = new Map<string, RegistryKey>();
  private currentKid: string | null = null;
  private inflight: Promise<RegistryKey> | null = null;
  private readonly registryUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly maxCacheTtlMs: number;
  private readonly requestTimeoutMs: number;

  constructor(opts: RegistryKeyDiscoveryOptions = {}) {
    this.registryUrl = validateRegistryUrl(
      opts.registryUrl ?? DEFAULT_REGISTRY,
      opts.dangerouslyAllowHttp ?? false,
    );
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.maxCacheTtlMs = opts.maxCacheTtlMs ?? MAX_CACHE_TTL_MS;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  /**
   * Returns the key for a specific `kid`. If we have it cached and
   * the cache is fresh, returns immediately. Otherwise re-fetches
   * the current key from the registry and returns it if its kid
   * matches the requested one.
   */
  async getKey(kid: string = DEFAULT_KID): Promise<RegistryKey> {
    const cached = this.byKid.get(kid);
    if (cached && cached.expiresAt.getTime() > Date.now()) {
      return cached;
    }
    const fresh = await this.refresh();
    if (fresh.kid !== kid) {
      // The registry has rotated to a kid we don't know about.
      // If we still have a non-expired cached entry for the
      // requested kid, prefer it (signature was from before the
      // rotation). Otherwise the requested kid is dead.
      if (cached) return cached;
      throw new MoltrustFirewallError(
        `registry signing key 'kid=${kid}' is no longer published (current is '${fresh.kid}')`,
        'unknown_kid',
      );
    }
    return fresh;
  }

  /** Re-fetches the current key from the registry, deduplicating concurrent calls. */
  async refresh(): Promise<RegistryKey> {
    if (this.inflight) return this.inflight;
    this.inflight = this.doFetch();
    try {
      return await this.inflight;
    } finally {
      this.inflight = null;
    }
  }

  private async doFetch(): Promise<RegistryKey> {
    const url = `${this.registryUrl}/.well-known/registry-key.json`;
    let response: Response;
    try {
      response = await fetchWithTimeout(
        this.fetchImpl,
        url,
        { method: 'GET', headers: defaultRequestHeaders() },
        this.requestTimeoutMs,
      );
    } catch (err) {
      if (err instanceof MoltrustFirewallError) throw err;
      throw new MoltrustFirewallError(
        `failed to fetch registry key from ${url}`,
        'fetch_failed',
        err,
      );
    }
    if (!response.ok) {
      throw new MoltrustFirewallError(
        `registry key endpoint returned HTTP ${response.status}`,
        'http_error',
      );
    }
    assertJsonResponse(response, url);
    // JWKs are tiny (~250B). Cap at 16KB to defend against compromised
    // registry serving a multi-GB body without a higher cost than a
    // few extra bytes overhead for legitimate responses.
    const jwk = await readJsonBoundedBody<JsonWebKey>(response, url, 16 * 1024);
    validateJwk(jwk);
    const publicKey = base64UrlDecode(jwk.x);
    if (publicKey.length !== 32) {
      throw new MoltrustFirewallError(
        `expected 32-byte Ed25519 public key, got ${publicKey.length} bytes`,
        'invalid_key_length',
      );
    }
    const ttlMs = parseCacheControl(response.headers.get('cache-control'), this.maxCacheTtlMs);
    const now = new Date();
    const key: RegistryKey = {
      kid: jwk.kid,
      alg: 'Ed25519',
      publicKey,
      raw: jwk,
      fetchedAt: now,
      expiresAt: new Date(now.getTime() + ttlMs),
    };
    this.byKid.set(jwk.kid, key);
    this.currentKid = jwk.kid;
    return key;
  }

  /** Returns the kid most recently returned by the registry (for diagnostics). */
  get latestKid(): string | null {
    return this.currentKid;
  }
}

function validateJwk(jwk: unknown): asserts jwk is JsonWebKey {
  if (!jwk || typeof jwk !== 'object') {
    throw new MoltrustFirewallError('JWK is not an object', 'invalid_jwk');
  }
  const j = jwk as Record<string, unknown>;
  if (j.kty !== 'OKP') {
    throw new MoltrustFirewallError(`expected kty='OKP', got '${String(j.kty)}'`, 'invalid_jwk');
  }
  if (j.crv !== 'Ed25519') {
    throw new MoltrustFirewallError(`expected crv='Ed25519', got '${String(j.crv)}'`, 'invalid_jwk');
  }
  if (typeof j.x !== 'string' || j.x.length === 0) {
    throw new MoltrustFirewallError('JWK missing x', 'invalid_jwk');
  }
  if (typeof j.kid !== 'string' || j.kid.length === 0) {
    throw new MoltrustFirewallError('JWK missing kid', 'invalid_jwk');
  }
  if (j.alg !== 'EdDSA') {
    throw new MoltrustFirewallError(`expected alg='EdDSA', got '${String(j.alg)}'`, 'invalid_jwk');
  }
}

function parseCacheControl(header: string | null, maxTtlMs: number): number {
  if (!header) return DEFAULT_CACHE_TTL_MS;
  const lower = header.toLowerCase();
  // Honour the registry's explicit no-cache directives by collapsing
  // to the library's floor (we always cache for at least MIN_CACHE_TTL_MS
  // so a steady-state warm key can still survive a brief 1-second
  // micro-burst of requests without re-fetching).
  if (/(?:^|[\s,])(?:no-store|no-cache|must-revalidate)\b/.test(lower)) {
    return MIN_CACHE_TTL_MS;
  }
  const m = /(?:^|[\s,])max-age\s*=\s*(\d+)/.exec(lower);
  if (!m) return DEFAULT_CACHE_TTL_MS;
  const seconds = Number.parseInt(m[1]!, 10);
  if (!Number.isFinite(seconds) || seconds <= 0) return MIN_CACHE_TTL_MS;
  const ms = Math.min(Math.max(seconds * 1000, MIN_CACHE_TTL_MS), maxTtlMs);
  return ms;
}

