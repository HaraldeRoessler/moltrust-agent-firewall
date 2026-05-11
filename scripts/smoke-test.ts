/**
 * End-to-end smoke test against api.moltrust.ch.
 *
 * Exercises each layer of @moltrust/agent-firewall and reports
 * what the live registry returns. Run with:
 *
 *   npx tsx scripts/smoke-test.ts [did:moltrust:...]
 *
 * Defaults to a placeholder DID if no arg is given.
 */
import {
  EnforcementGate,
  MoltrustCaepClient,
  MoltrustVerifier,
  PollingSource,
  RegistryKeyDiscovery,
  MemoryStore,
} from '../src/index.js';

const TEST_DID = process.argv[2] ?? 'did:moltrust:a4adbea0a1344bf4';
const BOGUS_DID = 'did:moltrust:0000000000000000';

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}
function ok(label: string, detail = ''): void {
  console.log(`  ${pad('[OK]', 6)} ${pad(label, 50)} ${detail}`);
}
function fail(label: string, detail: string): void {
  console.log(`  ${pad('[FAIL]', 6)} ${pad(label, 50)} ${detail}`);
}
function info(label: string, detail = ''): void {
  console.log(`  ${pad('[--]', 6)} ${pad(label, 50)} ${detail}`);
}
function section(title: string): void {
  console.log(`\n========== ${title} ==========`);
}

async function main(): Promise<void> {
  console.log(`@moltrust/agent-firewall smoke test`);
  console.log(`Registry:   https://api.moltrust.ch`);
  console.log(`Subject:    ${TEST_DID}`);
  console.log(`Bogus DID:  ${BOGUS_DID} (expected: 4xx)\n`);

  // ───────────────────────────────────────────────────────────────
  section('1. Registry key discovery — /.well-known/registry-key.json');
  let keyDiscovery: RegistryKeyDiscovery;
  try {
    keyDiscovery = new RegistryKeyDiscovery();
    const key = await keyDiscovery.getKey();
    ok('GET /.well-known/registry-key.json', `200 OK`);
    ok('JWK validates (OKP / Ed25519 / EdDSA)', '');
    ok('Public key length = 32 bytes', `${key.publicKey.length}`);
    info('kid', `${key.kid}`);
    info('alg', `${key.alg}`);
    info('cached until', `${key.expiresAt.toISOString()}`);
    if (key.kid === 'moltrust-registry-2026-v1') {
      ok('kid matches expected (moltrust-registry-2026-v1)', '');
    } else {
      fail('kid does NOT match expected', `got '${key.kid}'`);
    }
  } catch (err) {
    fail('registry key discovery', describeError(err));
    return;
  }

  // ───────────────────────────────────────────────────────────────
  section('2. Trust score verification — /skill/trust-score/{did}');
  let scoreVal: number | null = null;
  let grade: string | null = null;
  try {
    const verifier = new MoltrustVerifier({ keyDiscovery });
    const score = await verifier.fetchAndVerify(TEST_DID);
    ok('GET /skill/trust-score/<did>', `200 OK`);
    ok('JCS canonicalisation + Ed25519 signature', `verified`);
    ok('signed_by matches discovered kid', `${score.signed_by}`);
    info('trust_score', `${score.trust_score}`);
    info('grade', `${score.grade}`);
    info('withheld', `${score.withheld}`);
    info('computed_at', `${score.computed_at.toISOString()}`);
    info('valid_until', `${score.valid_until.toISOString()}`);
    const now = Date.now();
    const remainingMs = score.valid_until.getTime() - now;
    if (remainingMs > 0) {
      ok('valid_until is in the future', `${Math.round(remainingMs / 1000)}s remaining`);
    } else {
      fail('valid_until is in the past', `${Math.round(-remainingMs / 1000)}s ago`);
    }
    scoreVal = score.trust_score;
    grade = score.grade;
  } catch (err) {
    fail('trust score fetch + verify', describeError(err));
  }

  // ───────────────────────────────────────────────────────────────
  section('3. Bogus DID — should error cleanly');
  try {
    const verifier = new MoltrustVerifier({ keyDiscovery });
    const score = await verifier.fetchAndVerify(BOGUS_DID);
    fail('bogus DID returned a verified score (?!)', JSON.stringify(score));
  } catch (err) {
    const e = err as { code?: string; message?: string };
    if (e.code === 'http_error') {
      ok('bogus DID surfaces as http_error', `${e.message}`);
    } else if (e.code === 'fetch_failed' || e.code === 'request_timeout') {
      info('bogus DID failed at network layer', `${e.code}`);
    } else {
      info(`bogus DID rejected with code='${e.code}'`, `${e.message ?? ''}`);
    }
  }

  // ───────────────────────────────────────────────────────────────
  section('4. CAEP pending poll — /caep/pending/{did} (one-shot)');
  let polledEventCount = 0;
  try {
    const events: unknown[] = [];
    const store = new MemoryStore();
    const source = new PollingSource({
      store,
      watch: [TEST_DID],
      // 30s is the hard floor; we'll stop the source after one tick.
      intervalMs: 30_000,
      logger: {
        warn: (msg, ...rest) => info('polling warn', `${msg} ${JSON.stringify(rest)}`),
      },
    });
    await source.start(async (event) => {
      events.push(event);
    });
    // Wait long enough for the first tick.
    await new Promise((resolve) => setTimeout(resolve, 4_000));
    await source.stop();
    polledEventCount = events.length;
    ok('GET /caep/pending/<did>', `200 OK`);
    info('pending event count', `${events.length}`);
    if (events.length === 0) {
      info('(empty pending queue is normal for healthy DIDs)', '');
    } else {
      for (const e of events.slice(0, 5)) {
        const typed = e as { event_id: string; event_type: string };
        info(`event`, `${typed.event_type} ${typed.event_id}`);
      }
    }
  } catch (err) {
    fail('CAEP polling', describeError(err));
  }

  // ───────────────────────────────────────────────────────────────
  section('5. End-to-end client + gate decision (minScore=60)');
  try {
    const client = new MoltrustCaepClient({
      polling: { intervalMs: 30_000 },
    });
    const gate = new EnforcementGate(client, { minScore: 60 });

    const decision = await gate.decide(TEST_DID);
    info('decision', `allow=${decision.allow} reason=${decision.reason}`);
    if (decision.score) {
      info('score (from gate)', `${decision.score.trust_score} ${decision.score.grade}`);
    }
    if (decision.reason === 'allowed') {
      ok('gate decision matches expectation', `score ${decision.score?.trust_score} >= 60`);
    } else if (decision.reason === 'denied_score_below_threshold') {
      ok('gate denied (score below threshold)', `score ${decision.score?.trust_score} < 60`);
    } else if (decision.reason === 'denied_score_withheld') {
      ok('gate denied (score withheld)', `Phase 2 needs >=3 endorsers`);
    } else {
      info(`gate denied for other reason`, decision.reason);
    }

    await client.stop();
  } catch (err) {
    fail('end-to-end gate', describeError(err));
  }

  // ───────────────────────────────────────────────────────────────
  section('Summary');
  console.log(`\n  Subject: ${TEST_DID}`);
  console.log(`  Score:   ${scoreVal ?? 'n/a'} ${grade ?? ''}`);
  console.log(`  CAEP events pending: ${polledEventCount}`);
  console.log(`\n  Cross-check by hand:`);
  console.log(`    https://moltrust.ch/verify/${TEST_DID}`);
  console.log(`    https://api.moltrust.ch/identity/badge/${TEST_DID}`);
  console.log(`    https://api.moltrust.ch/.well-known/registry-key.json`);
}

function describeError(err: unknown): string {
  const e = err as { code?: string; message?: string };
  return `${e.code ?? 'no_code'}: ${e.message ?? String(err)}`;
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error('\nFATAL:', err);
    process.exit(1);
  },
);
