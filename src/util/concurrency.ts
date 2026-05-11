/**
 * Runs `fn` over `items` with at most `limit` tasks in flight at once.
 *
 * Used by ack flush to cap the burst load against the registry —
 * a backlog of thousands of pending acks would otherwise fire as
 * many simultaneous HTTP requests, exhausting the local HTTP
 * connection pool and overwhelming the upstream.
 *
 * Errors thrown by individual tasks are swallowed (caller decides
 * what "failure" means — typically `flushAcks` re-enqueues so the
 * next tick retries).
 */
export async function withConcurrency<T>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<void>,
  onError?: (err: unknown, item: T) => void,
): Promise<void> {
  if (items.length === 0) return;
  const cap = Math.max(1, Math.min(limit, items.length));
  let next = 0;
  const workers: Promise<void>[] = [];
  for (let i = 0; i < cap; i++) {
    workers.push(
      (async () => {
        while (true) {
          const index = next++;
          if (index >= items.length) return;
          const item = items[index];
          if (item === undefined) return;
          try {
            await fn(item);
          } catch (err) {
            // Per-task errors don't abort the batch (we still want
            // other items to run). Surface via the optional onError
            // callback so callers can log; absent that, the error
            // is swallowed (matching the prior contract).
            if (onError) {
              try {
                onError(err, item);
              } catch {
                /* onError itself shouldn't take down the worker */
              }
            }
          }
        }
      })(),
    );
  }
  await Promise.all(workers);
}
