import { MoltrustFirewallError, type CaepEvent, type Did } from '../types.js';

/**
 * Validates and normalises a registry base URL.
 *
 * - Strips trailing slash
 * - Refuses non-HTTPS unless `dangerouslyAllowHttp: true` is explicitly set
 *   (intended only for local registry mocks during development / tests).
 * - Refuses anything other than a syntactically valid http(s) URL.
 */
export function validateRegistryUrl(url: string, allowHttp = false): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new MoltrustFirewallError(
      `registryUrl is not a valid URL: '${url}'`,
      'invalid_registry_url',
    );
  }
  if (parsed.protocol !== 'https:' && !(allowHttp && parsed.protocol === 'http:')) {
    throw new MoltrustFirewallError(
      `registryUrl must use HTTPS (got '${parsed.protocol}'). Pass dangerouslyAllowHttp: true if you really need HTTP for local testing.`,
      'insecure_protocol',
    );
  }
  return url.replace(/\/$/, '');
}

/**
 * DID syntax check (W3C DID core, MolTrust-flavoured).
 *
 * Permissive enough to allow did:moltrust:, did:web:, did:ethr:, did:key:,
 * and the did:moltrust → ERC-8004 bridge identifiers the registry exposes,
 * while rejecting empty strings, control characters, embedded URL fragments,
 * and lengths beyond what any sane DID requires (256 chars).
 */
const DID_REGEX = /^did:[a-z0-9]+:[a-zA-Z0-9._:%-]{1,200}$/;

export function isValidDid(value: unknown): value is Did {
  return typeof value === 'string' && value.length <= 256 && DID_REGEX.test(value);
}

export function assertValidDid(value: unknown, context: string): asserts value is Did {
  if (!isValidDid(value)) {
    const safe = typeof value === 'string' ? value.slice(0, 60) : '(non-string)';
    throw new MoltrustFirewallError(
      `invalid DID '${safe}' (${context})`,
      'invalid_did',
    );
  }
}

/**
 * Shape validator for incoming CAEP events.
 *
 * The registry is a trusted upstream today, but defending against
 * malformed responses (network corruption, future bugs, malicious
 * proxies, schema drift) is cheap. Unknown event_type values are
 * permitted — consumers receive them via the generic 'event' channel
 * for forward compatibility.
 */
export function isValidCaepEvent(raw: unknown): raw is CaepEvent {
  if (!raw || typeof raw !== 'object') return false;
  const e = raw as Record<string, unknown>;
  if (typeof e.event_id !== 'string' || e.event_id.length === 0 || e.event_id.length > 256) {
    return false;
  }
  if (!isValidDid(e.subject_did)) return false;
  if (typeof e.event_type !== 'string' || e.event_type.length === 0 || e.event_type.length > 64) {
    return false;
  }
  if (typeof e.emitted_at !== 'string') return false;
  const ts = Date.parse(e.emitted_at);
  if (Number.isNaN(ts)) return false;
  if (e.payload === null || typeof e.payload !== 'object' || Array.isArray(e.payload)) {
    return false;
  }
  return true;
}

/**
 * Returns an AbortSignal that fires when ANY input signal fires.
 *
 * Prefers the built-in `AbortSignal.any` (Node 20.3+); falls back to
 * a manual fan-out for older runtimes so the library still works on
 * the Node 18 LTS line.
 */
export function combineSignals(signals: AbortSignal[]): AbortSignal {
  const native = (AbortSignal as unknown as { any?: (s: AbortSignal[]) => AbortSignal }).any;
  if (typeof native === 'function') return native(signals);
  const controller = new AbortController();
  for (const signal of signals) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      return controller.signal;
    }
    signal.addEventListener(
      'abort',
      () => {
        controller.abort(signal.reason);
      },
      { once: true },
    );
  }
  return controller.signal;
}

/**
 * Wraps a fetch call with a per-request timeout. Composes with any
 * caller-provided AbortSignal so existing cancellation still works.
 */
export async function fetchWithTimeout(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const signal = init.signal
    ? combineSignals([init.signal, timeoutSignal])
    : timeoutSignal;
  try {
    return await fetchImpl(url, { ...init, signal });
  } catch (err) {
    // Normalise the "request timed out" error to a stable shape so
    // callers can match on `code === 'request_timeout'`.
    if (timeoutSignal.aborted && !init.signal?.aborted) {
      throw new MoltrustFirewallError(
        `request to ${url} timed out after ${timeoutMs}ms`,
        'request_timeout',
        err,
      );
    }
    throw err;
  }
}

/** Constructs the Authorization / X-API-Key headers from caller options. */
export function buildAuthHeaders(opts: { apiKey?: string; bearerToken?: string }): Record<string, string> {
  const headers: Record<string, string> = {};
  if (opts.bearerToken) {
    headers['Authorization'] = `Bearer ${opts.bearerToken}`;
  } else if (opts.apiKey) {
    headers['X-API-Key'] = opts.apiKey;
  }
  return headers;
}
