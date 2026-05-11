import type { CaepEvent, Did } from '../types.js';

/**
 * Pluggable event delivery channel for CAEP events.
 *
 * v1.0.0 ships `PollingSource` (HTTP GET /caep/pending/{did}).
 * `XmtpSource` is reserved for the Q2/Q3 push channel — when the
 * MolTrust registry begins emitting events over the XMTP network,
 * a new EventSource implementation can be slotted in here without
 * any change to `MoltrustCaepClient` or its consumers.
 *
 * Sources are responsible for:
 *  - producing events for the DIDs they are configured to watch
 *  - calling `onEvent` exactly once per event (no duplicates)
 *  - calling `ack(eventId)` after the consumer signals success
 *    (acks are best-effort — the registry retains for 90 days)
 *  - stopping cleanly on `stop()` (cancelling any in-flight HTTP
 *    requests, timers, etc.)
 */
export interface EventSource {
  /** Begin emitting events to the supplied callback. */
  start(onEvent: (event: CaepEvent) => void | Promise<void>): Promise<void>;
  /** Mark `eventId` as acknowledged with the upstream channel. */
  ack(eventId: string): Promise<void>;
  /** Add a DID to the watch set; idempotent. */
  watch(did: Did): void;
  /** Remove a DID from the watch set; idempotent. */
  unwatch(did: Did): void;
  /** Stop the source and release any resources. */
  stop(): Promise<void>;
  /** Human-readable name for diagnostics (e.g. "polling", "xmtp"). */
  readonly name: string;
}
