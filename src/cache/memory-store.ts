import type { Did, Store } from '../types.js';

/**
 * In-process Store. Cursors and pending acks live in Maps and
 * disappear on process restart, which means after a restart the
 * client re-fetches everything still in the registry's 90-day
 * retention window (the registry is the source of truth — the
 * cursor is just a delivery-skip optimisation).
 *
 * Persistent stores (Redis, Postgres, etc.) are out of scope for
 * 1.0.0; bring your own by implementing the Store interface.
 */
export interface MemoryStoreOptions {
  /**
   * Suppress the runtime warning emitted on construction. Useful in
   * test suites and short-lived CLI tools where the operator is
   * aware of the non-persistent nature of this store.
   */
  silent?: boolean;
}

export class MemoryStore implements Store {
  private cursors = new Map<Did, string>();
  private pendingAcks = new Set<string>();
  private static warned = false;

  constructor(opts: MemoryStoreOptions = {}) {
    if (!opts.silent && !MemoryStore.warned) {
      MemoryStore.warned = true;
      process.emitWarning(
        'PollingSource is using MemoryStore (default). Cursors and pending acks ' +
          'live in process memory and disappear on restart — after a restart, ' +
          'every watched DID re-fetches from the registry\'s 90-day retention ' +
          'window, which can cause a thundering herd of duplicate event ' +
          'replays. Production deployments should implement the `Store` interface ' +
          'against Redis / Postgres / disk and pass it as `polling.store`.',
        'MoltrustMemoryStoreWarning',
      );
    }
  }

  async getCursor(did: Did): Promise<string | null> {
    return this.cursors.get(did) ?? null;
  }

  async setCursor(did: Did, cursor: string): Promise<void> {
    this.cursors.set(did, cursor);
  }

  async enqueueAck(eventId: string): Promise<void> {
    this.pendingAcks.add(eventId);
  }

  async drainAcks(): Promise<string[]> {
    const ids = Array.from(this.pendingAcks);
    this.pendingAcks.clear();
    return ids;
  }
}
