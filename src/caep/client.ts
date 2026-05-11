import { EventEmitter } from 'node:events';

import {
  DEFAULT_REGISTRY,
  MoltrustFirewallError,
  PROFILE_ID,
  type CaepEvent,
  type CaepEventType,
  type Did,
  type VerifiedTrustScore,
} from '../types.js';
import { MoltrustVerifier } from '../verify/verifier.js';
import { TrustCache } from '../cache/trust-cache.js';
import { PollingSource, type PollingSourceOptions } from './polling-source.js';
import type { EventSource } from './source.js';
import { assertValidDid, validateRegistryUrl } from '../util/security.js';

/** Max bytes for flag payload values — defensive cap against compromised-registry log/memory blowup. */
const MAX_FLAG_LENGTH = 256;

/** Minimum interval between distinct fetches for the same DID. */
const DEFAULT_MIN_FETCH_INTERVAL_MS = 1_000;

/** How often the rate-limiter sweeps stale entries, at most. */
const LAST_FETCH_SWEEP_INTERVAL_MS = 30_000;

function extractFlag(value: unknown, onTruncated?: (originalLength: number) => void): string {
  if (typeof value !== 'string') return '';
  if (value.length > MAX_FLAG_LENGTH) {
    onTruncated?.(value.length);
    return value.slice(0, MAX_FLAG_LENGTH);
  }
  return value;
}

/** Strongly-typed event map for `MoltrustCaepClient`. */
export interface MoltrustCaepClientEvents {
  /** Any CAEP event observed from any source, before per-type fan-out. */
  event: [event: CaepEvent];
  /** Score change for a DID. Emitted after the verifier confirms the new score. */
  trust_score_change: [score: VerifiedTrustScore, raw: CaepEvent];
  /** DID was revoked. Cache entry is invalidated before the listener runs. */
  did_revoked: [did: Did, raw: CaepEvent];
  flag_added: [did: Did, flag: string, raw: CaepEvent];
  flag_removed: [did: Did, flag: string, raw: CaepEvent];
  /** Underlying source returned an error from a poll. */
  error: [error: unknown];
}

export interface MoltrustCaepClientOptions {
  /** Registry base URL. Default: https://api.moltrust.ch. */
  registryUrl?: string;
  /** Custom fetch (mostly for tests). */
  fetchImpl?: typeof fetch;
  /** DIDs to watch from start. More can be added later via `watch()`. */
  watch?: Did[];
  /** Provide your own source instead of the default `PollingSource`. */
  source?: EventSource;
  /** When using the default polling source, options forwarded to it. */
  polling?: PollingSourceOptions;
  /** Pre-built verifier (reused if you already created one elsewhere). */
  verifier?: MoltrustVerifier;
  /** Pre-built cache. */
  cache?: TrustCache;
  /**
   * On `trust_score_change`, re-fetch + verify the new score automatically
   * and emit `trust_score_change` with the verified payload. Default: true.
   *
   * Set to false if you don't want network calls inside the event loop and
   * prefer to receive the raw event via `client.on('event', ...)`.
   */
  autoVerify?: boolean;
  /**
   * Allow `http://` URLs for the registry. NEVER set in production —
   * cleartext HTTP would expose DIDs, scores, and any API key in
   * transit. Local-mock testing only.
   *
   * When set at this top level, the flag is propagated consistently
   * to the internal verifier, registry-key discovery, and polling
   * source. (You can also set `polling.dangerouslyAllowHttp`, but
   * mixing the two is discouraged — prefer this top-level option.)
   */
  dangerouslyAllowHttp?: boolean;
  /**
   * CAEP profile v1 does NOT sign individual events. `trust_score_change`
   * is safe because the client re-fetches the signed score before
   * emitting the typed event. `did_revoked`, `flag_added`, and
   * `flag_removed` are NOT independently verified — a network
   * attacker between the consumer and the registry could fabricate
   * them.
   *
   * When `dropUnsignedEvents: true`, the typed handlers for those
   * three event types are suppressed (events still pass through the
   * generic `'event'` channel for diagnostics, so consumers can
   * still observe them, just not act on them via the strong-typed
   * handlers).
   *
   * **Default: true** (secure-by-default — typed handlers fire only
   * for cryptographically-verified events). Pass `false` to opt in
   * to acting on unsigned events; the client emits a Node
   * `process.emitWarning` on start when this is set so operators
   * can audit insecure configurations centrally.
   *
   * The registry's roadmap includes signed CAEP envelopes — once
   * shipped, that work will land here as Profile v2 and this option
   * will become a no-op for verified events.
   */
  dropUnsignedEvents?: boolean;
  /**
   * Minimum wall-clock interval between consecutive `getVerifiedScore`
   * network fetches for the same DID. Defaults to 1000ms. Within this
   * window, repeated calls return the cached score even if its
   * `valid_until` has passed; once the interval elapses, the next call
   * is allowed to re-fetch.
   *
   * The cache + this rate limit together prevent tight-loop callers
   * (and accidentally-broken control flow) from hammering the registry
   * — the singleflight protects against concurrent storms; this
   * protects against serial loops.
   */
  minFetchIntervalMs?: number;
  /**
   * Optional logger for non-fatal client-internal events (auto-verify
   * failures, truncated flags, etc.). Defaults to silent.
   */
  logger?: { warn?(msg: string, ...meta: unknown[]): void; debug?(msg: string, ...meta: unknown[]): void };
}

/**
 * Consumer for the MolTrust CAEP Profile v1.
 *
 * Wires together:
 *  - an `EventSource` (PollingSource by default)
 *  - a `MoltrustVerifier` for signed trust scores
 *  - a `TrustCache` for fast `getVerifiedScore(did)` lookups
 *
 * Emits typed events (`trust_score_change`, `did_revoked`, etc.)
 * that callers can wire directly into their firewall / gateway
 * decision logic.
 *
 * This client implements the polling profile only. The Q2/Q3 XMTP
 * push channel will plug in as a different `EventSource` without
 * changing this class.
 */
export class MoltrustCaepClient extends EventEmitter {
  public readonly profile = PROFILE_ID;
  public readonly verifier: MoltrustVerifier;
  public readonly cache: TrustCache;
  public readonly source: EventSource;
  private readonly autoVerify: boolean;
  private readonly dropUnsignedEvents: boolean;
  private readonly minFetchIntervalMs: number;
  private readonly inflightFetches = new Map<Did, Promise<VerifiedTrustScore>>();
  /**
   * Wall-clock ms at which we last (started) a verifier fetch for this DID.
   * Lazy-swept on access — see `sweepStaleFetchTimestamps`.
   */
  private readonly lastFetchAt = new Map<Did, number>();
  private lastSweepAt = 0;
  private readonly logger: Required<MoltrustCaepClientOptions>['logger'];
  private started = false;

  constructor(opts: MoltrustCaepClientOptions = {}) {
    super();
    // Allow either the top-level or polling.* form, defaulting to the
    // safer (HTTPS-only) value. The top-level flag wins if both are
    // set, since it's the new canonical surface.
    const allowHttp =
      opts.dangerouslyAllowHttp ?? opts.polling?.dangerouslyAllowHttp ?? false;
    const registryUrl = validateRegistryUrl(
      opts.registryUrl ?? DEFAULT_REGISTRY,
      allowHttp,
    );
    const fetchImpl = opts.fetchImpl ?? fetch;
    for (const did of opts.watch ?? []) assertValidDid(did, 'MoltrustCaepClient.watch');
    this.verifier =
      opts.verifier ??
      new MoltrustVerifier({ registryUrl, fetchImpl, dangerouslyAllowHttp: allowHttp });
    this.cache = opts.cache ?? new TrustCache();
    this.source =
      opts.source ??
      new PollingSource({
        registryUrl,
        fetchImpl,
        dangerouslyAllowHttp: allowHttp,
        ...(opts.watch ? { watch: opts.watch } : {}),
        ...(opts.polling ?? {}),
      });
    this.autoVerify = opts.autoVerify ?? true;
    // Secure-by-default: unsigned CAEP events (did_revoked, flag_*) are
    // dropped from typed handlers unless the operator explicitly opts in.
    this.dropUnsignedEvents = opts.dropUnsignedEvents ?? true;
    this.minFetchIntervalMs = Math.max(0, opts.minFetchIntervalMs ?? DEFAULT_MIN_FETCH_INTERVAL_MS);
    this.logger = opts.logger ?? {};
    // EventEmitter default is 10 — too low for fan-out into per-tenant
    // gates or many gateway instances. 0 = unlimited; the application
    // is in a better position than the library to bound listener counts.
    this.setMaxListeners(0);
  }

  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    if (!this.dropUnsignedEvents) {
      process.emitWarning(
        'MoltrustCaepClient started with dropUnsignedEvents=false. ' +
          'did_revoked / flag_* events are passed to typed handlers without ' +
          'cryptographic verification. A network attacker (TLS MitM, ' +
          'compromised proxy) could fabricate them. See PROFILE.md for context.',
        'MoltrustInsecureEventsWarning',
      );
    }
    await this.source.start((event) => this.handle(event));
  }

  async stop(): Promise<void> {
    if (!this.started) return;
    this.started = false;
    await this.source.stop();
  }

  /** Add a DID to the watch set on the underlying source. */
  watch(did: Did): void {
    assertValidDid(did, 'MoltrustCaepClient.watch');
    this.source.watch(did);
  }

  /** Remove a DID from the watch set. */
  unwatch(did: Did): void {
    assertValidDid(did, 'MoltrustCaepClient.unwatch');
    this.source.unwatch(did);
  }

  /**
   * Returns a cached verified trust score if one is held and still
   * within its `valid_until`. Otherwise fetches and verifies a fresh
   * one (which also populates the cache).
   *
   * Concurrent calls for the same DID with no cached score are
   * deduplicated via single-flight — only one network request is
   * made; all callers await the same Promise. This bounds the
   * outbound rate to the registry to roughly the number of distinct
   * DIDs being asked about, not the number of callers.
   *
   * Callers in tight loops should still rate-limit themselves —
   * the singleflight protects against burst storms across concurrent
   * requests, but a serial loop without `await` between iterations
   * will still fan out into rapid sequential fetches once each
   * preceding one resolves.
   */
  async getVerifiedScore(did: Did): Promise<VerifiedTrustScore> {
    assertValidDid(did, 'MoltrustCaepClient.getVerifiedScore');
    const cached = this.cache.get(did);
    if (cached) return cached;
    const existing = this.inflightFetches.get(did);
    if (existing) return existing;
    // Rate limit per DID: refuse to issue a new fetch within
    // `minFetchIntervalMs` of the previous one. Protects against
    // serial-loop misuse that the singleflight (concurrent dedup)
    // alone cannot catch.
    const now = Date.now();
    const last = this.lastFetchAt.get(did);
    if (last !== undefined && now - last < this.minFetchIntervalMs) {
      const remaining = this.minFetchIntervalMs - (now - last);
      throw new MoltrustFirewallError(
        `getVerifiedScore for ${did} called within ${remaining}ms of the previous fetch; ` +
          `wait at least ${remaining}ms before retrying (or rely on the cache)`,
        'rate_limited_client',
      );
    }
    this.lastFetchAt.set(did, now);
    this.sweepStaleFetchTimestamps(now);
    const promise = this.verifier
      .fetchAndVerify(did)
      .then((score) => {
        this.cache.set(score);
        return score;
      })
      .finally(() => {
        this.inflightFetches.delete(did);
      });
    this.inflightFetches.set(did, promise);
    return promise;
  }

  // EventEmitter typing — overrides to give callers strong types.
  override on<K extends keyof MoltrustCaepClientEvents>(
    event: K,
    listener: (...args: MoltrustCaepClientEvents[K]) => void,
  ): this {
    return super.on(event, listener as (...args: unknown[]) => void);
  }

  override once<K extends keyof MoltrustCaepClientEvents>(
    event: K,
    listener: (...args: MoltrustCaepClientEvents[K]) => void,
  ): this {
    return super.once(event, listener as (...args: unknown[]) => void);
  }

  override off<K extends keyof MoltrustCaepClientEvents>(
    event: K,
    listener: (...args: MoltrustCaepClientEvents[K]) => void,
  ): this {
    return super.off(event, listener as (...args: unknown[]) => void);
  }

  override emit<K extends keyof MoltrustCaepClientEvents>(
    event: K,
    ...args: MoltrustCaepClientEvents[K]
  ): boolean {
    return super.emit(event, ...args);
  }

  /**
   * Lazily prunes `lastFetchAt` entries older than 2× the rate-limit
   * window — they no longer constrain anything. Runs at most once
   * every `LAST_FETCH_SWEEP_INTERVAL_MS`. Bounds memory for long-running
   * processes watching many distinct DIDs.
   */
  private sweepStaleFetchTimestamps(now: number): void {
    if (now - this.lastSweepAt < LAST_FETCH_SWEEP_INTERVAL_MS) return;
    this.lastSweepAt = now;
    const threshold = now - this.minFetchIntervalMs * 2;
    for (const [did, t] of this.lastFetchAt) {
      if (t < threshold) this.lastFetchAt.delete(did);
    }
  }

  private async handle(raw: CaepEvent): Promise<void> {
    this.emit('event', raw);
    try {
      switch (raw.event_type as CaepEventType) {
        case 'trust_score_change': {
          this.cache.invalidate(raw.subject_did);
          if (this.autoVerify) {
            const verified = await this.verifier.fetchAndVerify(raw.subject_did);
            this.cache.set(verified);
            this.emit('trust_score_change', verified, raw);
          }
          break;
        }
        case 'did_revoked': {
          this.cache.invalidate(raw.subject_did);
          if (!this.dropUnsignedEvents) {
            this.emit('did_revoked', raw.subject_did, raw);
          }
          break;
        }
        case 'flag_added': {
          if (!this.dropUnsignedEvents) {
            const flag = extractFlag(raw.payload['flag'], (original) =>
              this.logger.warn?.(
                `truncated oversized flag value from ${original} to ${MAX_FLAG_LENGTH} chars (event ${raw.event_id})`,
              ),
            );
            this.emit('flag_added', raw.subject_did, flag, raw);
          }
          break;
        }
        case 'flag_removed': {
          if (!this.dropUnsignedEvents) {
            const flag = extractFlag(raw.payload['flag'], (original) =>
              this.logger.warn?.(
                `truncated oversized flag value from ${original} to ${MAX_FLAG_LENGTH} chars (event ${raw.event_id})`,
              ),
            );
            this.emit('flag_removed', raw.subject_did, flag, raw);
          }
          break;
        }
        default:
          // Unknown event types are reported only via the generic
          // 'event' channel — forward-compatibility for future
          // protocol extensions without breaking consumers.
          break;
      }
    } catch (err) {
      // EventEmitter convention: emitting 'error' with no listeners
      // throws an uncaught exception that crashes the process. Guard
      // by checking listener count first; if none, log via the
      // optional logger and swallow.
      if (this.listenerCount('error') > 0) {
        this.emit('error', err);
      } else {
        this.logger.warn?.('CAEP event handler threw (no \'error\' listener attached)', err);
      }
    }
  }
}
