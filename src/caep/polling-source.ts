import {
  DEFAULT_REGISTRY,
  MoltrustFirewallError,
  RATE_LIMIT_PER_HOUR_PER_DID,
  type CaepEvent,
  type CaepPendingResponse,
  type Did,
  type Store,
} from '../types.js';
import { MemoryStore } from '../cache/memory-store.js';
import {
  assertJsonResponse,
  assertValidDid,
  buildAuthHeaders,
  defaultRequestHeaders,
  fetchWithTimeout,
  isValidCaepEvent,
  readJsonBoundedBody,
  summariseCaepEvent,
  validateRegistryUrl,
} from '../util/security.js';
import { withConcurrency } from '../util/concurrency.js';
import type { EventSource } from './source.js';

export interface PollingSourceOptions {
  /** Registry base URL (default: https://api.moltrust.ch). */
  registryUrl?: string;
  /** Custom fetch implementation (default: global fetch). */
  fetchImpl?: typeof fetch;
  /** Persistence backend for cursors and pending acks (default: MemoryStore). */
  store?: Store;
  /** Initial set of DIDs to watch. */
  watch?: Did[];
  /**
   * Base interval (ms) between polls per DID. Default 30s
   * (= 120 polls/h, exactly matching the registry rate limit
   * — pick a higher value to leave headroom for retries).
   */
  intervalMs?: number;
  /** Maximum events to request per poll (default 100, max 500). */
  pageLimit?: number;
  /** Cap on consecutive failures before a DID's poller backs off to `maxBackoffMs`. */
  maxBackoffMs?: number;
  /** Per-request HTTP timeout in ms (default 10s). */
  requestTimeoutMs?: number;
  /** Max concurrent ack POSTs per flush cycle (default 10). */
  ackConcurrency?: number;
  /**
   * Max times a failed ack is re-queued before being dropped (default 5).
   * Dropping is safe — acks are best-effort; the registry retains events
   * for 90 days, and the polling cursor has already advanced past them.
   */
  maxAckRetries?: number;
  /**
   * Hard cap on the number of DIDs this source watches at once
   * (default 10_000). `watch()` throws `MoltrustFirewallError(code:
   * 'too_many_watched_dids')` if exceeded. Guards memory if `watch()`
   * is reachable from untrusted / unbounded input (e.g. a gateway
   * that auto-watches every new counterparty DID).
   */
  maxWatchedDids?: number;
  /**
   * How often pending acks are flushed (default 5000 ms). High-volume
   * consumers can tune this lower; idle consumers can raise it.
   */
  ackDrainIntervalMs?: number;
  /**
   * Optional API key sent as `X-API-Key`. Prefer `bearerToken` for
   * Authorization: Bearer style. Mutually exclusive — `bearerToken` wins.
   */
  apiKey?: string;
  /** Optional bearer token sent as `Authorization: Bearer ...`. */
  bearerToken?: string;
  /**
   * Allow http:// registry URLs. NEVER use in production — would
   * expose DIDs, scores, and any API key in transit. Local testing only.
   */
  dangerouslyAllowHttp?: boolean;
  /** Optional console-style logger for non-fatal events (default: silent). */
  logger?: { warn?(msg: string, ...meta: unknown[]): void; debug?(msg: string, ...meta: unknown[]): void };
}

const MIN_INTERVAL_MS = (60 * 60 * 1000) / RATE_LIMIT_PER_HOUR_PER_DID; // 30000 ms
const DEFAULT_INTERVAL_MS = MIN_INTERVAL_MS;
const DEFAULT_MAX_BACKOFF_MS = 15 * 60 * 1000;
const ACK_DRAIN_INTERVAL_MS = 5_000;
const MAX_PAGE_LIMIT = 500;
const DEFAULT_PAGE_LIMIT = 100;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_ACK_CONCURRENCY = 10;
const DEFAULT_MAX_ACK_RETRIES = 5;
const DEFAULT_MAX_WATCHED_DIDS = 10_000;

interface PerDidState {
  did: Did;
  timer: ReturnType<typeof setTimeout> | null;
  consecutiveFailures: number;
  inflight: AbortController | null;
}

/**
 * Polling implementation of `EventSource` against
 * GET /caep/pending/{did}?since=<cursor>&limit=<n>.
 *
 * - One independent poll loop per watched DID
 * - Per-DID exponential backoff on errors (jittered, capped)
 * - Honours the registry's published rate limit (120/h/DID)
 * - Cursor and pending acks persisted via the supplied `Store`
 * - Pending acks are batched and flushed every 5s
 */
export class PollingSource implements EventSource {
  public readonly name = 'polling';

  private readonly registryUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly store: Store;
  private readonly intervalMs: number;
  private readonly pageLimit: number;
  private readonly maxBackoffMs: number;
  private readonly requestTimeoutMs: number;
  private readonly ackConcurrency: number;
  private readonly maxAckRetries: number;
  private readonly maxWatchedDids: number;
  private readonly ackDrainIntervalMs: number;
  /** event_id → retry attempts so far. Capped by `maxAckRetries`. */
  private readonly ackRetries = new Map<string, number>();
  private readonly headers: Record<string, string>;
  private readonly logger: Required<PollingSourceOptions>['logger'];
  private readonly states = new Map<Did, PerDidState>();

  private onEvent: ((event: CaepEvent) => void | Promise<void>) | null = null;
  private ackTimer: ReturnType<typeof setInterval> | null = null;
  private stopped = false;
  /** When non-null, a flush is in flight — `stop()` awaits it before returning. */
  private flushAcksPromise: Promise<void> | null = null;
  /** Wall-clock ms until which ack flushes should be paused (set by 429 Retry-After). */
  private ackPauseUntil = 0;

  constructor(opts: PollingSourceOptions = {}) {
    this.registryUrl = validateRegistryUrl(
      opts.registryUrl ?? DEFAULT_REGISTRY,
      opts.dangerouslyAllowHttp ?? false,
    );
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.store = opts.store ?? new MemoryStore();
    const requested = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.intervalMs = Math.max(MIN_INTERVAL_MS, requested);
    this.pageLimit = clamp(opts.pageLimit ?? DEFAULT_PAGE_LIMIT, 1, MAX_PAGE_LIMIT);
    this.maxBackoffMs = opts.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.ackConcurrency = Math.max(1, opts.ackConcurrency ?? DEFAULT_ACK_CONCURRENCY);
    this.maxAckRetries = Math.max(0, opts.maxAckRetries ?? DEFAULT_MAX_ACK_RETRIES);
    this.maxWatchedDids = Math.max(1, opts.maxWatchedDids ?? DEFAULT_MAX_WATCHED_DIDS);
    this.ackDrainIntervalMs = Math.max(1_000, opts.ackDrainIntervalMs ?? ACK_DRAIN_INTERVAL_MS);
    const authOpts: { apiKey?: string; bearerToken?: string } = {};
    if (opts.apiKey !== undefined) authOpts.apiKey = opts.apiKey;
    if (opts.bearerToken !== undefined) authOpts.bearerToken = opts.bearerToken;
    this.headers = {
      ...defaultRequestHeaders(),
      ...buildAuthHeaders(authOpts),
    };
    this.logger = opts.logger ?? {};
    for (const did of opts.watch ?? []) {
      assertValidDid(did, 'PollingSource.watch');
      if (this.states.size >= this.maxWatchedDids) {
        throw new MoltrustFirewallError(
          `cannot watch more than ${this.maxWatchedDids} DIDs (set maxWatchedDids to raise the cap)`,
          'too_many_watched_dids',
        );
      }
      this.states.set(did, makeState(did));
    }
  }

  async start(onEvent: (event: CaepEvent) => void | Promise<void>): Promise<void> {
    if (this.onEvent) {
      throw new MoltrustFirewallError('PollingSource is already started', 'already_started');
    }
    if (this.stopped) {
      throw new MoltrustFirewallError('PollingSource has been stopped and cannot be restarted', 'stopped');
    }
    this.onEvent = onEvent;
    for (const state of this.states.values()) this.schedule(state, 0);
    this.ackTimer = setInterval(() => {
      void this.flushAcks();
    }, this.ackDrainIntervalMs);
    if (this.ackTimer.unref) this.ackTimer.unref();
  }

  watch(did: Did): void {
    assertValidDid(did, 'PollingSource.watch');
    if (this.states.has(did)) return;
    if (this.states.size >= this.maxWatchedDids) {
      throw new MoltrustFirewallError(
        `cannot watch more than ${this.maxWatchedDids} DIDs (set maxWatchedDids to raise the cap)`,
        'too_many_watched_dids',
      );
    }
    const state = makeState(did);
    this.states.set(did, state);
    if (this.onEvent && !this.stopped) this.schedule(state, 0);
  }

  unwatch(did: Did): void {
    const state = this.states.get(did);
    if (!state) return;
    if (state.timer) clearTimeout(state.timer);
    if (state.inflight) state.inflight.abort();
    this.states.delete(did);
  }

  async ack(eventId: string): Promise<void> {
    await this.store.enqueueAck(eventId);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.ackTimer) {
      clearInterval(this.ackTimer);
      this.ackTimer = null;
    }
    for (const state of this.states.values()) {
      if (state.timer) clearTimeout(state.timer);
      if (state.inflight) state.inflight.abort();
    }
    this.states.clear();
    // If a previous flush is in flight, wait for it to settle (so
    // we don't drop acks on shutdown). Then run one final flush to
    // drain anything still pending in the store.
    if (this.flushAcksPromise) {
      try {
        await this.flushAcksPromise;
      } catch (err) {
        this.logger.warn?.('in-flight ack flush errored during stop()', err);
      }
    }
    await this.flushAcks();
    this.onEvent = null;
  }

  private schedule(state: PerDidState, delayMs: number): void {
    if (state.timer) clearTimeout(state.timer);
    state.timer = setTimeout(() => {
      void this.tick(state);
    }, delayMs);
    if (state.timer.unref) state.timer.unref();
  }

  private async tick(state: PerDidState): Promise<void> {
    if (this.stopped || !this.onEvent || !this.states.has(state.did)) return;
    // Allocate the AbortController BEFORE any await so `stop()` /
    // `unwatch()` can cancel this tick mid-flight, even during the
    // getCursor() round-trip.
    const ac = new AbortController();
    state.inflight = ac;
    try {
      const cursor = await this.store.getCursor(state.did);
      // Re-check shutdown/unwatch after every await — the orchestrator
      // may have transitioned state during the store I/O above.
      if (this.stopped || !this.onEvent || !this.states.has(state.did) || ac.signal.aborted) return;
      const events = await this.poll(state, cursor, ac);
      if (this.stopped || !this.onEvent || !this.states.has(state.did) || ac.signal.aborted) return;
      for (const evt of events) {
        try {
          await this.onEvent(evt);
        } catch (err) {
          this.logger.warn?.(`onEvent handler threw for event ${evt.event_id}`, err);
          // We still ack — a throwing handler shouldn't pin the cursor.
        }
        await this.store.enqueueAck(evt.event_id);
        await this.store.setCursor(state.did, evt.event_id);
        if (this.stopped || !this.states.has(state.did)) return;
      }
      state.consecutiveFailures = 0;
      this.schedule(state, this.intervalMs);
    } catch (err) {
      // Permanent HTTP errors (4xx other than 429) won't get better by
      // retrying. Stop polling this DID and log loudly so an operator
      // can intervene (unwatch / re-register / fix the API key / etc.).
      const e = err as { code?: string };
      if (e.code === 'http_permanent_error') {
        this.logger.warn?.(
          `polling for ${state.did} hit a permanent HTTP error; unwatching ` +
            `(re-call .watch() after fixing the underlying issue)`,
          err,
        );
        this.unwatch(state.did);
        return;
      }
      state.consecutiveFailures += 1;
      const delay = backoffDelay(state.consecutiveFailures, this.intervalMs, this.maxBackoffMs);
      this.logger.warn?.(
        `polling failed for ${state.did} (attempt ${state.consecutiveFailures}); retrying in ${Math.round(delay / 1000)}s`,
        err,
      );
      this.schedule(state, delay);
    }
  }

  private async poll(state: PerDidState, cursor: string | null, ac: AbortController): Promise<CaepEvent[]> {
    const params = new URLSearchParams();
    params.set('limit', String(this.pageLimit));
    if (cursor) params.set('since', cursor);
    const url = `${this.registryUrl}/caep/pending/${encodeURIComponent(state.did)}?${params.toString()}`;
    let response: Response;
    try {
      response = await fetchWithTimeout(
        this.fetchImpl,
        url,
        { method: 'GET', headers: this.headers, signal: ac.signal },
        this.requestTimeoutMs,
      );
    } finally {
      state.inflight = null;
    }
    if (response.status === 429) {
      const retryAfter = response.headers.get('retry-after');
      const ms = retryAfter ? Number.parseInt(retryAfter, 10) * 1000 : this.intervalMs * 2;
      throw new MoltrustFirewallError(
        `registry rate-limited polling for ${state.did}; retry after ${ms}ms`,
        'rate_limited',
        { retryAfterMs: ms },
      );
    }
    if (!response.ok) {
      // 4xx (except 429) means the request itself is bad — DID not
      // registered, malformed cursor, auth issue. No amount of
      // retrying will fix it. Surface a different code so the
      // poll loop can stop wasting cycles on this DID.
      const code = response.status >= 400 && response.status < 500 ? 'http_permanent_error' : 'http_error';
      throw new MoltrustFirewallError(
        `GET /caep/pending/${state.did} returned HTTP ${response.status}`,
        code,
      );
    }
    assertJsonResponse(response, url);
    // 2 MiB cap: a full-page CAEP response (500 events, each
    // ~300B) fits in well under 200KB. The cap protects against a
    // compromised registry serving a multi-GB body without
    // foreclosing on realistic bursts.
    const body = await readJsonBoundedBody<CaepPendingResponse>(response, url, 2 * 1024 * 1024);
    if (!body || !Array.isArray(body.events)) {
      throw new MoltrustFirewallError(
        'malformed CAEP pending response (missing events array)',
        'malformed_response',
      );
    }
    const valid: CaepEvent[] = [];
    for (const raw of body.events) {
      if (isValidCaepEvent(raw)) {
        valid.push(raw);
      } else {
        // Log only a length-capped, non-control-char summary — the
        // raw event is registry-supplied and could be log-injection-
        // shaped or megabyte-scale. summariseCaepEvent extracts only
        // canonical envelope fields with truncation.
        this.logger.warn?.(
          `dropping malformed CAEP event from polling source`,
          summariseCaepEvent(raw),
        );
      }
    }
    return valid;
  }

  private async flushAcks(): Promise<void> {
    if (this.flushAcksPromise) {
      this.logger.debug?.('flushAcks: previous drain still in flight; tick skipped');
      return this.flushAcksPromise;
    }
    if (this.ackPauseUntil > Date.now()) {
      this.logger.debug?.(
        `flushAcks: paused for ${Math.round((this.ackPauseUntil - Date.now()) / 1000)}s (registry 429 Retry-After)`,
      );
      return;
    }
    this.flushAcksPromise = (async () => {
      try {
        const ids = await this.store.drainAcks();
        if (ids.length === 0) return;
        // Cap concurrent ack POSTs. A 10k-event backlog after a
        // restart would otherwise fire 10k simultaneous fetches and
        // exhaust the local HTTP pool / spike the registry.
        await withConcurrency(
          ids,
          this.ackConcurrency,
          async (id) => {
            await this.sendAck(id);
          },
          // Concurrency-level errors are already individually
          // logged in sendAck; surface unexpected throws so they
          // don't silently disappear.
          (err) => this.logger.warn?.('unexpected error during ack flush', err),
        );
      } finally {
        this.flushAcksPromise = null;
      }
    })();
    return this.flushAcksPromise;
  }

  /** 4xx (except 429) is permanent — request itself is bad. Never retry. */
  private isPermanentAckFailure(status: number): boolean {
    return status >= 400 && status < 500 && status !== 429;
  }

  private async sendAck(eventId: string): Promise<void> {
    if (!eventId || typeof eventId !== 'string' || eventId.length > 256) {
      this.logger.warn?.(`refusing to ack malformed event id`);
      this.ackRetries.delete(eventId);
      return;
    }
    const url = `${this.registryUrl}/caep/acknowledge/${encodeURIComponent(eventId)}`;
    let outcome: 'success' | 'transient' | 'permanent';
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        url,
        { method: 'POST', headers: this.headers },
        this.requestTimeoutMs,
      );
      if (response.ok) {
        outcome = 'success';
      } else if (this.isPermanentAckFailure(response.status)) {
        outcome = 'permanent';
        this.logger.warn?.(
          `ack for ${eventId} returned HTTP ${response.status} (permanent); dropping`,
        );
      } else {
        outcome = 'transient';
        if (response.status === 429) {
          // Respect the registry's hint when available. The next drain
          // tick is the granularity we control — if the suggested delay
          // is shorter, just take the next tick; otherwise pause future
          // drains accordingly.
          const retryAfter = parseRetryAfter(response.headers.get('retry-after'));
          if (retryAfter !== null) {
            this.logger.warn?.(
              `ack for ${eventId} hit 429; honouring Retry-After: ${Math.round(retryAfter / 1000)}s`,
            );
            this.ackPauseUntil = Math.max(this.ackPauseUntil, Date.now() + retryAfter);
          }
        } else {
          this.logger.warn?.(
            `ack for ${eventId} returned HTTP ${response.status}; will retry`,
          );
        }
      }
    } catch (err) {
      outcome = 'transient';
      this.logger.warn?.(`ack for ${eventId} failed (transient); will retry`, err);
    }

    if (outcome === 'success') {
      this.ackRetries.delete(eventId);
      this.logger.debug?.(`acked ${eventId}`);
      return;
    }
    if (outcome === 'permanent') {
      this.ackRetries.delete(eventId);
      return;
    }
    // Transient: re-enqueue if under the retry cap; otherwise drop.
    // Dropping is safe — acks are best-effort and the registry retains
    // events for 90 days; the polling cursor has already advanced.
    const attempts = (this.ackRetries.get(eventId) ?? 0) + 1;
    if (attempts >= this.maxAckRetries) {
      this.ackRetries.delete(eventId);
      this.logger.warn?.(
        `ack for ${eventId} exceeded ${this.maxAckRetries} retries; dropping ` +
          `(safe — registry retains events for 90 days)`,
      );
      return;
    }
    this.ackRetries.set(eventId, attempts);
    await this.store.enqueueAck(eventId);
  }
}

function makeState(did: Did): PerDidState {
  return { did, timer: null, consecutiveFailures: 0, inflight: null };
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(Math.max(n, lo), hi);
}

function backoffDelay(attempt: number, baseMs: number, maxMs: number): number {
  const exp = Math.min(maxMs, baseMs * 2 ** (attempt - 1));
  const jitter = exp * 0.25 * Math.random();
  return Math.floor(exp + jitter);
}

/**
 * Parses a `Retry-After` header value into milliseconds.
 *
 * Accepts:
 *   - delta-seconds: `Retry-After: 30`
 *   - RFC 7231 IMF-fixdate: `Retry-After: Wed, 11 May 2026 17:00:00 GMT`
 *
 * Older HTTP-date formats (RFC 850, asctime) are rejected — they
 * exist in the spec but are nominally obsolete, and `Date.parse`'s
 * willingness to accept formats like `"tomorrow"` or `"05-11-2026"`
 * could otherwise let a misbehaving registry pin the client for
 * an extended (but still clamped) window.
 *
 * The returned delay is clamped to `[0, 1 hour]` regardless.
 */
function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const trimmed = value.trim();
  let ms: number;
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number.parseInt(trimmed, 10);
    if (!Number.isFinite(seconds)) return null;
    ms = seconds * 1000;
  } else if (IMF_FIXDATE_REGEX.test(trimmed)) {
    const date = Date.parse(trimmed);
    if (Number.isNaN(date)) return null;
    ms = Math.max(0, date - Date.now());
  } else {
    return null;
  }
  return Math.min(Math.max(ms, 0), 60 * 60 * 1000);
}

/**
 * Strict RFC 7231 IMF-fixdate matcher. Format:
 *   Sun, 06 Nov 1994 08:49:37 GMT
 * Day name + 2-digit day + 3-letter month + 4-digit year + HH:MM:SS GMT.
 */
const IMF_FIXDATE_REGEX =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;
