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
    // Don't reflect the raw input — enterprise registry URLs can
    // contain internal hostnames and (mis-pasted) credentials. The
    // caller already knows the value they passed.
    const safe = typeof url === 'string' ? `(string of length ${url.length})` : `(non-string: ${typeof url})`;
    throw new MoltrustFirewallError(
      `registryUrl is not a valid URL ${safe}`,
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
 *
 * Library-wide DID-handling policy:
 *
 *   1. **Inputs are sanitised in errors.** When validation fails in
 *      `assertValidDid`, the rejected value is NEVER reflected into
 *      the error message — only its shape and length. The caller may
 *      have accidentally passed a credential, PII, or an internal
 *      identifier that shouldn't bleed into observability pipelines.
 *
 *   2. **Validated DIDs ARE public.** Once a string has passed
 *      `assertValidDid`, it is a syntactically valid DID and is
 *      treated as public-by-design — DIDs are intended to be shared
 *      and resolved (e.g. https://moltrust.ch/verify/did:moltrust:...
 *      is a public web page). Including them in subsequent errors,
 *      audit logs, and metrics is intentional, not a leak.
 *
 *   3. **isValidDid is syntax-only, not normalisation.** Percent
 *      sequences (e.g. did:web:host%3A8080) are permitted because the
 *      DID Core spec uses them. Downstream consumers that depend on
 *      semantic equality should percent-decode before comparison.
 */
const DID_REGEX = /^did:[a-z0-9]+:[a-zA-Z0-9._:%-]{1,200}$/;

export function isValidDid(value: unknown): value is Did {
  return typeof value === 'string' && value.length <= 256 && DID_REGEX.test(value);
}

export function assertValidDid(value: unknown, context: string): asserts value is Did {
  if (!isValidDid(value)) {
    // Don't reflect the value verbatim — a misuse-passed credential or
    // PII fragment shouldn't bleed into logs / observability pipes via
    // this error. Report only the kind and length, which is enough
    // for the caller to identify their bug without exposing content.
    const shape =
      typeof value !== 'string'
        ? `(non-string: ${typeof value})`
        : value.length === 0
          ? '(empty string)'
          : `(string of length ${value.length})`;
    throw new MoltrustFirewallError(
      `invalid DID ${shape} (${context})`,
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

/**
 * Asserts that a Response carries an `application/json` Content-Type.
 *
 * Defends against a misconfigured (or malicious) registry serving
 * text/html / text/javascript that `response.json()` would happily
 * try to parse, masking an unexpected content path or making
 * any reflected body harder to reason about.
 */
export function assertJsonResponse(response: Response, url: string): void {
  const ct = response.headers.get('content-type') ?? '';
  if (!ct.toLowerCase().includes('application/json')) {
    throw new MoltrustFirewallError(
      `expected application/json from ${sanitiseUrl(url)}, got '${ct || '(none)'}'`,
      'unexpected_content_type',
    );
  }
}

/**
 * Default cap for any response body read by this library. Trust-score
 * responses are ~500B, JWKs ~250B, and a fully-packed CAEP page
 * (500 events) maxes out around ~150KB — 1 MiB is several orders of
 * magnitude above legitimate sizes while staying well clear of a
 * compromised-registry memory-exhaustion attack.
 */
export const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

/**
 * Reads a Response body with an enforced size cap and parses it as
 * JSON. Rejects (with `MoltrustFirewallError(code: 'response_too_large')`)
 * if Content-Length is declared and exceeds `maxBytes`, OR if the
 * streamed body cumulatively exceeds `maxBytes` mid-read (covers
 * chunked responses that omit Content-Length).
 *
 * Defends against a compromised registry / MITM serving a multi-GB
 * body that `response.json()` would happily slurp into memory within
 * the per-request timeout window.
 */
export async function readJsonBoundedBody<T>(
  response: Response,
  url: string,
  maxBytes: number = DEFAULT_MAX_RESPONSE_BYTES,
): Promise<T> {
  const contentLength = response.headers.get('content-length');
  if (contentLength) {
    const declared = Number.parseInt(contentLength, 10);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new MoltrustFirewallError(
        `response from ${sanitiseUrl(url)} declares Content-Length ${declared} bytes, exceeds cap ${maxBytes}`,
        'response_too_large',
      );
    }
  }
  if (!response.body) {
    // No body — caller-shape problem rather than security one.
    throw new MoltrustFirewallError(
      `response from ${sanitiseUrl(url)} has no body`,
      'empty_body',
    );
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          /* best-effort */
        }
        throw new MoltrustFirewallError(
          `response body from ${sanitiseUrl(url)} exceeded cap of ${maxBytes} bytes`,
          'response_too_large',
        );
      }
      chunks.push(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* lock may already be released by cancel() */
    }
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(merged);
  try {
    return JSON.parse(text) as T;
  } catch (err) {
    throw new MoltrustFirewallError(
      `response from ${sanitiseUrl(url)} is not valid JSON`,
      'invalid_json',
      err,
    );
  }
}

/**
 * Returns a sanitised representation of a URL for safe inclusion in
 * error messages and logs. Strips path, query, fragment, and any
 * userinfo so internal hostnames and credentials don't leak into
 * observability pipelines.
 */
export function sanitiseUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    // Couldn't parse as a URL — show only the leading 40 chars,
    // ASCII-only, so logs stay grep-friendly without bleeding content.
    const safe = url.slice(0, 40).replace(/[^\x20-\x7e]/g, '?');
    return `(unparseable URL: ${safe})`;
  }
}

/**
 * Returns a small, safe summary of a CAEP event for logging when
 * validation fails. Includes only the canonical envelope fields,
 * truncated to safe lengths, and reports the value type rather than
 * the value itself for the payload (which is registry-supplied and
 * could be log-injection-shaped).
 */
export function summariseCaepEvent(raw: unknown): Record<string, string> {
  const summary: Record<string, string> = { _raw_type: typeof raw };
  if (!raw || typeof raw !== 'object') return summary;
  const e = raw as Record<string, unknown>;
  const truncate = (s: unknown, n: number): string =>
    typeof s === 'string' ? s.slice(0, n).replace(/[^\x20-\x7e]/g, '?') : `(${typeof s})`;
  summary['event_id'] = truncate(e['event_id'], 40);
  summary['event_type'] = truncate(e['event_type'], 40);
  summary['subject_did'] = truncate(e['subject_did'], 80);
  summary['emitted_at'] = truncate(e['emitted_at'], 40);
  summary['payload_type'] = e['payload'] === null ? 'null' : Array.isArray(e['payload']) ? 'array' : typeof e['payload'];
  return summary;
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
