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
  // JCS accepts any JSON value (object, array, string, number, boolean, null).
  // Anything else — undefined, functions, symbols, BigInt — is non-serialisable
  // and should be rejected before reaching the canonicaliser, where it would
  // either return undefined or silently coerce.
  const t = typeof payload;
  if (
    payload === undefined ||
    t === 'function' ||
    t === 'symbol' ||
    t === 'bigint'
  ) {
    throw new MoltrustFirewallError(
      `JCS input is not a JSON value (got ${payload === undefined ? 'undefined' : t})`,
      'jcs_unserialisable',
    );
  }
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
