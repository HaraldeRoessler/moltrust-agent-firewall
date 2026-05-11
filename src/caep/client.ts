import { EventEmitter } from 'node:events';

import {
  DEFAULT_REGISTRY,
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
   * Default: false (events processed as-is). The registry's roadmap
   * includes signed CAEP envelopes — once shipped, that work will
   * land here as Profile v2.
   */
  dropUnsignedEvents?: boolean;
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
  private started = false;

  constructor(opts: MoltrustCaepClientOptions = {}) {
    super();
    const registryUrl = validateRegistryUrl(
      opts.registryUrl ?? DEFAULT_REGISTRY,
      opts.polling?.dangerouslyAllowHttp ?? false,
    );
    const fetchImpl = opts.fetchImpl ?? fetch;
    for (const did of opts.watch ?? []) assertValidDid(did, 'MoltrustCaepClient.watch');
    this.verifier =
      opts.verifier ??
      new MoltrustVerifier({ registryUrl, fetchImpl });
    this.cache = opts.cache ?? new TrustCache();
    this.source =
      opts.source ??
      new PollingSource({
        registryUrl,
        fetchImpl,
        ...(opts.watch ? { watch: opts.watch } : {}),
        ...(opts.polling ?? {}),
      });
    this.autoVerify = opts.autoVerify ?? true;
    this.dropUnsignedEvents = opts.dropUnsignedEvents ?? false;
  }

  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
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
   */
  async getVerifiedScore(did: Did): Promise<VerifiedTrustScore> {
    assertValidDid(did, 'MoltrustCaepClient.getVerifiedScore');
    const cached = this.cache.get(did);
    if (cached) return cached;
    const fresh = await this.verifier.fetchAndVerify(did);
    this.cache.set(fresh);
    return fresh;
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
            const flag = typeof raw.payload['flag'] === 'string' ? raw.payload['flag'] : '';
            this.emit('flag_added', raw.subject_did, flag, raw);
          }
          break;
        }
        case 'flag_removed': {
          if (!this.dropUnsignedEvents) {
            const flag = typeof raw.payload['flag'] === 'string' ? raw.payload['flag'] : '';
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
      this.emit('error', err);
    }
  }
}
