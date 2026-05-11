/**
 * Minimal example: watch one DID, log every event, deny actions
 * for DIDs whose verified score falls below 60.
 *
 * Run with:
 *   npx tsx examples/basic-usage.ts
 */
import { EnforcementGate, MoltrustCaepClient } from '../src/index.js';

const WATCH_DID = process.argv[2] ?? 'did:moltrust:a4adbea0a1344bf4';

async function main(): Promise<void> {
  const client = new MoltrustCaepClient({
    watch: [WATCH_DID],
    polling: {
      logger: {
        warn: (msg, ...rest) => console.warn('[firewall]', msg, ...rest),
      },
    },
  });

  client.on('event', (raw) => {
    console.log('[event]', raw.event_type, raw.subject_did, raw.event_id);
  });
  client.on('trust_score_change', (verified) => {
    console.log(
      '[score change]',
      verified.did,
      `→ ${verified.score} (${verified.grade}), valid until ${verified.valid_until.toISOString()}`,
    );
  });
  client.on('did_revoked', (did) => {
    console.warn('[revoked]', did);
  });
  client.on('error', (err) => {
    console.error('[error]', err);
  });

  const gate = new EnforcementGate(client, { minScore: 60 });

  await client.start();

  // Demonstrate a one-shot decision call.
  try {
    const decision = await gate.decide(WATCH_DID);
    console.log('[decision]', WATCH_DID, decision);
  } catch (err) {
    console.error('[decision failed]', err);
  }

  // Keep running until SIGINT.
  process.on('SIGINT', () => {
    console.log('shutting down…');
    void client.stop().then(() => process.exit(0));
  });
}

void main();
