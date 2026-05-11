/**
 * @moltrust/agent-firewall — consumer library for the MolTrust
 * trust registry.
 *
 * Implements the MolTrust CAEP Profile v1 (polling) plus signed
 * trust-score verification (RFC 8785 JCS + Ed25519).
 *
 * See PROFILE.md for the wire-protocol description.
 */

import { MoltrustFirewallError } from './types.js';

// Runtime engine check — package.json declares engines.node >= 18, but
// that's advisory unless engine-strict is enabled in npm config. The
// library uses AbortSignal.timeout which lands in Node 17.3+; throwing
// here gives operators a clear error at module load rather than an
// obscure "AbortSignal.timeout is not a function" later.
if (typeof AbortSignal === 'undefined' || typeof AbortSignal.timeout !== 'function') {
  throw new MoltrustFirewallError(
    '@moltrust/agent-firewall requires Node 18 or later (AbortSignal.timeout is unavailable).',
    'unsupported_runtime',
  );
}

export {
  DEFAULT_KID,
  DEFAULT_REGISTRY,
  MoltrustFirewallError,
  PROFILE_ID,
  PROFILE_VERSION,
  RATE_LIMIT_PER_HOUR_PER_DID,
  type CaepEvent,
  type CaepEventType,
  type CaepPendingResponse,
  type Did,
  type DidRevokedPayload,
  type FlagPayload,
  type JsonWebKey,
  type RegistryKey,
  type SignedTrustScoreResponse,
  type Store,
  type TrustScoreChangePayload,
  type VerifiedTrustScore,
} from './types.js';

export { jcsCanonicalize } from './verify/jcs.js';
export { RegistryKeyDiscovery, type RegistryKeyDiscoveryOptions } from './verify/registry-key.js';
export { MoltrustVerifier, type VerifierOptions } from './verify/verifier.js';

export { MemoryStore } from './cache/memory-store.js';
export { TrustCache, type TrustCacheOptions } from './cache/trust-cache.js';

export type { EventSource } from './caep/source.js';
export { PollingSource, type PollingSourceOptions } from './caep/polling-source.js';
export {
  MoltrustCaepClient,
  type MoltrustCaepClientEvents,
  type MoltrustCaepClientOptions,
} from './caep/client.js';

export { EnforcementGate, type GateDecision, type GateOptions } from './firewall/gate.js';

export {
  assertJsonResponse,
  assertValidDid,
  base64UrlDecode,
  DEFAULT_MAX_RESPONSE_BYTES,
  isStrictIso8601,
  isValidCaepEvent,
  isValidDid,
  readJsonBoundedBody,
  sanitiseUrl,
  summariseCaepEvent,
  USER_AGENT,
  validateRegistryUrl,
} from './util/security.js';
export { withConcurrency } from './util/concurrency.js';
