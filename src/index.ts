/**
 * @moltrust/agent-firewall — consumer library for the MolTrust
 * trust registry.
 *
 * Implements the MolTrust CAEP Profile v1 (polling) plus signed
 * trust-score verification (RFC 8785 JCS + Ed25519).
 *
 * See PROFILE.md for the wire-protocol description.
 */
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

export { jcsCanonicalize, trustScoreSigningInput } from './verify/jcs.js';
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
