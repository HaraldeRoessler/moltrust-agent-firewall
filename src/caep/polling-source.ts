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
  assertValidDid,
  buildAuthHeaders,
  fetchWithTimeout,
  isValidCaepEvent,
  validateRegistryUrl,
} from '../util/security.js';
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
  private readonly headers: Record<string, string>;
  private readonly logger: Required<PollingSourceOptions>['logger'];
  private readonly states = new Map<Did, PerDidState>();

  private onEvent: ((event: CaepEvent) => void | Promise<void>) | null = null;
  private ackTimer: ReturnType<typeof setInterval> | null = null;
  private stopped = false;

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
    const authOpts: { apiKey?: string; bearerToken?: string } = {};
    if (opts.apiKey !== undefined) authOpts.apiKey = opts.apiKey;
    if (opts.bearerToken !== undefined) authOpts.bearerToken = opts.bearerToken;
    this.headers = {
      Accept: 'application/json',
      ...buildAuthHeaders(authOpts),
    };
    this.logger = opts.logger ?? {};
    for (const did of opts.watch ?? []) {
      assertValidDid(did, 'PollingSource.watch');
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
    }, ACK_DRAIN_INTERVAL_MS);
    if (this.ackTimer.unref) this.ackTimer.unref();
  }

  watch(did: Did): void {
    assertValidDid(did, 'PollingSource.watch');
    if (this.states.has(did)) return;
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
    // Last best-effort ack flush.
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
    if (this.stopped || !this.onEvent) return;
    if (!this.states.has(state.did)) return; // unwatched during the sleep
    try {
      const cursor = await this.store.getCursor(state.did);
      const events = await this.poll(state, cursor);
      for (const evt of events) {
        try {
          await this.onEvent(evt);
        } catch (err) {
          this.logger.warn?.(`onEvent handler threw for event ${evt.event_id}`, err);
          // We still ack — a throwing handler shouldn't pin the cursor.
        }
        await this.store.enqueueAck(evt.event_id);
        await this.store.setCursor(state.did, evt.event_id);
      }
      state.consecutiveFailures = 0;
      this.schedule(state, this.intervalMs);
    } catch (err) {
      state.consecutiveFailures += 1;
      const delay = backoffDelay(state.consecutiveFailures, this.intervalMs, this.maxBackoffMs);
      this.logger.warn?.(
        `polling failed for ${state.did} (attempt ${state.consecutiveFailures}); retrying in ${Math.round(delay / 1000)}s`,
        err,
      );
      this.schedule(state, delay);
    }
  }

  private async poll(state: PerDidState, cursor: string | null): Promise<CaepEvent[]> {
    const params = new URLSearchParams();
    params.set('limit', String(this.pageLimit));
    if (cursor) params.set('since', cursor);
    const url = `${this.registryUrl}/caep/pending/${encodeURIComponent(state.did)}?${params.toString()}`;
    const ac = new AbortController();
    state.inflight = ac;
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
      throw new MoltrustFirewallError(
        `GET /caep/pending/${state.did} returned HTTP ${response.status}`,
        'http_error',
      );
    }
    const body = (await response.json()) as CaepPendingResponse;
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
        this.logger.warn?.(
          `dropping malformed CAEP event from /caep/pending/${state.did}`,
          { raw },
        );
      }
    }
    return valid;
  }

  private async flushAcks(): Promise<void> {
    const ids = await this.store.drainAcks();
    if (ids.length === 0) return;
    await Promise.allSettled(ids.map(async (id) => this.sendAck(id)));
  }

  private async sendAck(eventId: string): Promise<void> {
    if (!eventId || typeof eventId !== 'string' || eventId.length > 256) {
      this.logger.warn?.(`refusing to ack malformed event id`);
      return;
    }
    const url = `${this.registryUrl}/caep/acknowledge/${encodeURIComponent(eventId)}`;
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        url,
        { method: 'POST', headers: this.headers },
        this.requestTimeoutMs,
      );
      if (!response.ok) {
        // Re-queue and let the next drain retry; the registry holds events for 90d.
        await this.store.enqueueAck(eventId);
        this.logger.warn?.(`ack for ${eventId} returned HTTP ${response.status}; re-queued`);
      } else {
        this.logger.debug?.(`acked ${eventId}`);
      }
    } catch (err) {
      await this.store.enqueueAck(eventId);
      this.logger.warn?.(`ack for ${eventId} failed; re-queued`, err);
    }
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
