import { describe, expect, it } from 'vitest';
import { jcsCanonicalize, trustScoreSigningInput } from '../src/verify/jcs.js';

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
});

describe('trustScoreSigningInput', () => {
  it('omits the registry_signature field but includes everything else', () => {
    const input = {
      did: 'did:moltrust:abc',
      score: 75,
      grade: 'B',
      computed_at: '2026-05-11T12:00:00Z',
      valid_until: '2026-05-11T13:00:00Z',
      withheld: false,
      registry_signature: { kid: 'k', alg: 'Ed25519', signature: 'deadbeef' },
    };
    const bytes = trustScoreSigningInput(input);
    const text = new TextDecoder().decode(bytes);
    expect(text).not.toContain('registry_signature');
    expect(text).toContain('"did":"did:moltrust:abc"');
    expect(text).toContain('"score":75');
  });

  it('throws when registry_signature is missing', () => {
    expect(() => trustScoreSigningInput({ did: 'x' })).toThrowError(/missing registry_signature/);
  });
});
