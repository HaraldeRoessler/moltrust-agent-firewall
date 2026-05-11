import { describe, expect, it } from 'vitest';
import { jcsCanonicalize } from '../src/verify/jcs.js';

describe('jcsCanonicalize', () => {
  it('sorts object keys lexicographically', () => {
    const a = jcsCanonicalize({ b: 1, a: 2 });
    const b = jcsCanonicalize({ a: 2, b: 1 });
    expect(new TextDecoder().decode(a)).toBe('{"a":2,"b":1}');
    expect(new TextDecoder().decode(b)).toBe('{"a":2,"b":1}');
  });

  it('preserves array order', () => {
    const out = jcsCanonicalize([3, 1, 2]);
    expect(new TextDecoder().decode(out)).toBe('[3,1,2]');
  });

  it('escapes strings per RFC 8259', () => {
    const out = jcsCanonicalize({ k: 'a\nb' });
    expect(new TextDecoder().decode(out)).toBe('{"k":"a\\nb"}');
  });

  it('produces the deterministic 5-field signing input the registry uses', () => {
    // Mirrors app/signature.py build_score_signing_payload on the registry.
    const payload = {
      did: 'did:moltrust:abc',
      trust_score: null,
      computed_at: '2026-05-11T12:00:00Z',
      valid_until: '2026-05-11T13:00:00Z',
      policy_version: 'phase2',
    };
    const text = new TextDecoder().decode(jcsCanonicalize(payload));
    // Keys sorted lexicographically; null stays as null.
    expect(text).toBe(
      '{"computed_at":"2026-05-11T12:00:00Z","did":"did:moltrust:abc","policy_version":"phase2","trust_score":null,"valid_until":"2026-05-11T13:00:00Z"}',
    );
  });
});
