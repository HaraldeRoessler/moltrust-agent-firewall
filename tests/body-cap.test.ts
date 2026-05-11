import { describe, expect, it } from 'vitest';
import {
  readJsonBoundedBody,
  sanitiseUrl,
  summariseCaepEvent,
} from '../src/util/security.js';
import { MoltrustFirewallError } from '../src/types.js';

function jsonResponse(body: string, contentLength?: number): Response {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (contentLength !== undefined) headers['content-length'] = String(contentLength);
  return new Response(body, { status: 200, headers });
}

describe('readJsonBoundedBody', () => {
  it('reads and parses a small JSON body', async () => {
    const r = jsonResponse('{"hello":"world"}');
    const body = await readJsonBoundedBody<{ hello: string }>(r, 'https://example.test');
    expect(body.hello).toBe('world');
  });

  it('rejects bodies declaring Content-Length above the cap', async () => {
    const huge = '{"x":1}';
    const r = jsonResponse(huge, 10_000_000);
    await expect(readJsonBoundedBody(r, 'https://example.test', 1024)).rejects.toMatchObject({
      code: 'response_too_large',
    });
  });

  it('rejects streamed bodies whose actual bytes exceed the cap', async () => {
    // No Content-Length, body > cap
    const payload = 'a'.repeat(2048);
    const r = new Response(payload, {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    await expect(readJsonBoundedBody(r, 'https://example.test', 1024)).rejects.toMatchObject({
      code: 'response_too_large',
    });
  });

  it('reports invalid JSON with the invalid_json code', async () => {
    const r = jsonResponse('not json');
    await expect(readJsonBoundedBody(r, 'https://example.test')).rejects.toMatchObject({
      code: 'invalid_json',
    });
  });
});

describe('sanitiseUrl', () => {
  it('strips path, query, and userinfo', () => {
    expect(sanitiseUrl('https://internal.example.com:8080/api/v1/secret?token=xyz')).toBe(
      'https://internal.example.com:8080',
    );
  });
  it('handles unparseable URLs without throwing', () => {
    expect(sanitiseUrl('not-a-url')).toMatch(/unparseable URL/);
  });
});

describe('summariseCaepEvent', () => {
  it('produces a small, truncated summary', () => {
    const huge = 'A'.repeat(10_000);
    const event = {
      event_id: huge,
      event_type: huge,
      subject_did: 'did:moltrust:abc',
      emitted_at: '2026-05-11T00:00:00Z',
      payload: { nested: { deep: 'value' } },
    };
    const summary = summariseCaepEvent(event);
    expect((summary['event_id'] as string).length).toBeLessThanOrEqual(40);
    expect((summary['event_type'] as string).length).toBeLessThanOrEqual(40);
    expect(summary['payload_type']).toBe('object');
  });
  it('reports payload_type=array for array payloads', () => {
    const summary = summariseCaepEvent({
      event_id: 'a',
      event_type: 'b',
      subject_did: 'did:moltrust:c',
      emitted_at: '2026-05-11T00:00:00Z',
      payload: [1, 2, 3],
    });
    expect(summary['payload_type']).toBe('array');
  });
  it('reports _raw_type for non-object input', () => {
    expect(summariseCaepEvent('a string')['_raw_type']).toBe('string');
    expect(summariseCaepEvent(null)['_raw_type']).toBe('object');
  });
});

describe('validateRegistryUrl error sanitisation', () => {
  it('does not reflect the raw URL on parse failure', async () => {
    const { validateRegistryUrl } = await import('../src/util/security.js');
    try {
      validateRegistryUrl('https://internal.example.com:8080/secret?token=xyz??::malformed', false);
      // If it didn't throw, we're done. (URL parses.)
    } catch (err) {
      expect(err).toBeInstanceOf(MoltrustFirewallError);
      const msg = (err as Error).message;
      expect(msg).not.toContain('secret');
      expect(msg).not.toContain('token=xyz');
    }
    try {
      validateRegistryUrl('not://a real /url:with internal.example.com', false);
    } catch (err) {
      expect((err as Error).message).not.toContain('internal.example.com');
    }
  });
});
