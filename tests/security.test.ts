import { describe, expect, it } from 'vitest';
import {
  assertValidDid,
  isValidCaepEvent,
  isValidDid,
  validateRegistryUrl,
} from '../src/util/security.js';
import { MoltrustFirewallError } from '../src/types.js';

describe('validateRegistryUrl', () => {
  it('accepts https URLs and strips trailing slash', () => {
    expect(validateRegistryUrl('https://api.moltrust.ch/')).toBe('https://api.moltrust.ch');
    expect(validateRegistryUrl('https://example.test:8443/api/')).toBe('https://example.test:8443/api');
  });
  it('rejects http URLs by default', () => {
    expect(() => validateRegistryUrl('http://api.moltrust.ch')).toThrowError(/HTTPS/);
  });
  it('allows http URLs when dangerouslyAllowHttp is true', () => {
    expect(validateRegistryUrl('http://localhost:8080', true)).toBe('http://localhost:8080');
  });
  it('rejects malformed URLs', () => {
    expect(() => validateRegistryUrl('not-a-url')).toThrowError(/valid URL/);
  });
  it('rejects ftp / file / other protocols even with allowHttp', () => {
    expect(() => validateRegistryUrl('ftp://example.test', true)).toThrowError(/HTTPS/);
    expect(() => validateRegistryUrl('file:///etc/passwd', true)).toThrowError(/HTTPS/);
  });
});

describe('isValidDid', () => {
  it('accepts canonical did:moltrust: identifiers', () => {
    expect(isValidDid('did:moltrust:a4adbea0a1344bf4')).toBe(true);
    expect(isValidDid('did:moltrust:0000000000000000')).toBe(true);
  });
  it('accepts other DID methods (did:web, did:key)', () => {
    expect(isValidDid('did:web:example.com')).toBe(true);
    expect(isValidDid('did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6')).toBe(true);
  });
  it('rejects empty strings', () => {
    expect(isValidDid('')).toBe(false);
  });
  it('rejects non-DID strings', () => {
    expect(isValidDid('https://example.com')).toBe(false);
    expect(isValidDid('not-a-did')).toBe(false);
  });
  it('rejects strings beyond 256 chars', () => {
    expect(isValidDid(`did:moltrust:${'a'.repeat(300)}`)).toBe(false);
  });
  it('rejects non-strings', () => {
    expect(isValidDid(null)).toBe(false);
    expect(isValidDid(undefined)).toBe(false);
    expect(isValidDid({ did: 'x' })).toBe(false);
    expect(isValidDid(123)).toBe(false);
  });
  it('rejects DIDs with shell-injection-like characters', () => {
    expect(isValidDid('did:moltrust:abc;rm -rf /')).toBe(false);
    expect(isValidDid('did:moltrust:abc\nfoo')).toBe(false);
    expect(isValidDid('did:moltrust:abc def')).toBe(false);
  });
});

describe('assertValidDid', () => {
  it('throws MoltrustFirewallError with code invalid_did on bad input', () => {
    try {
      assertValidDid('', 'test');
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(MoltrustFirewallError);
      expect((err as MoltrustFirewallError).code).toBe('invalid_did');
    }
  });
  it('does not throw on valid input', () => {
    expect(() => assertValidDid('did:moltrust:a4adbea0a1344bf4', 'test')).not.toThrow();
  });
});

describe('isValidCaepEvent', () => {
  const good = {
    event_id: 'evt_1',
    subject_did: 'did:moltrust:a4adbea0a1344bf4',
    event_type: 'trust_score_change',
    emitted_at: '2026-05-11T17:42:00Z',
    payload: { new_score: 82 },
  };
  it('accepts a well-formed event', () => {
    expect(isValidCaepEvent(good)).toBe(true);
  });
  it('rejects events missing required fields', () => {
    expect(isValidCaepEvent({ ...good, event_id: undefined })).toBe(false);
    expect(isValidCaepEvent({ ...good, subject_did: 'not-a-did' })).toBe(false);
    expect(isValidCaepEvent({ ...good, event_type: '' })).toBe(false);
    expect(isValidCaepEvent({ ...good, emitted_at: 'not-a-date' })).toBe(false);
    expect(isValidCaepEvent({ ...good, payload: 'string' })).toBe(false);
    expect(isValidCaepEvent({ ...good, payload: null })).toBe(false);
    expect(isValidCaepEvent({ ...good, payload: [1, 2, 3] })).toBe(false);
  });
  it('rejects non-objects', () => {
    expect(isValidCaepEvent(null)).toBe(false);
    expect(isValidCaepEvent('event')).toBe(false);
    expect(isValidCaepEvent(42)).toBe(false);
  });
  it('rejects an unreasonably long event_id', () => {
    expect(isValidCaepEvent({ ...good, event_id: 'a'.repeat(300) })).toBe(false);
  });
  it('accepts unknown event_type values (forward compatibility)', () => {
    expect(isValidCaepEvent({ ...good, event_type: 'future_event_type_we_dont_know_yet' })).toBe(true);
  });
});
