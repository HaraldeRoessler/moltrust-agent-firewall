import canonicalize from 'canonicalize';
import { MoltrustFirewallError } from '../types.js';

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * The registry signs trust-score responses over the JCS encoding of
 * the response with `registry_signature` removed. This helper does
 * the field-strip and canonicalisation in one place so both ends of
 * the signature can stay in lockstep.
 */
export function jcsCanonicalize(payload: unknown): Uint8Array {
  const out = canonicalize(payload as object);
  if (out === undefined) {
    throw new MoltrustFirewallError(
      'JCS canonicalisation returned undefined (input is not JSON-serialisable)',
      'jcs_unserialisable',
    );
  }
  return new TextEncoder().encode(out);
}

/**
 * Returns the byte sequence the registry signed for a trust-score
 * response — the JCS of every field except `registry_signature`.
 */
export function trustScoreSigningInput(
  response: Record<string, unknown>,
): Uint8Array {
  if (!('registry_signature' in response)) {
    throw new MoltrustFirewallError(
      'trust-score response is missing registry_signature',
      'missing_signature',
    );
  }
  const { registry_signature: _omitted, ...rest } = response;
  return jcsCanonicalize(rest);
}
