import { describe, expect, it } from 'vitest';
import { EnforcementGate } from '../src/firewall/gate.js';
import { MoltrustCaepClient } from '../src/caep/client.js';
import { MoltrustFirewallError } from '../src/types.js';

/** Minimal client double — overrides only the methods the gate touches. */
function clientThatThrows(err: unknown): MoltrustCaepClient {
  const client = new MoltrustCaepClient({});
  (client as unknown as { getVerifiedScore: () => Promise<never> }).getVerifiedScore = async () => {
    throw err;
  };
  return client;
}

describe('EnforcementGate error handling', () => {
  it('treats network failures as transient (denies by default)', async () => {
    const err = new MoltrustFirewallError('boom', 'fetch_failed');
    const gate = new EnforcementGate(clientThatThrows(err));
    const decision = await gate.decide('did:moltrust:abc');
    expect(decision.allow).toBe(false);
    expect(decision.reason).toBe('denied_transient_error');
    expect(decision.errorCode).toBe('fetch_failed');
  });

  it('fails open on transient errors when transientErrorPolicy=allow', async () => {
    const err = new MoltrustFirewallError('timeout', 'request_timeout');
    const gate = new EnforcementGate(clientThatThrows(err), { transientErrorPolicy: 'allow' });
    const decision = await gate.decide('did:moltrust:abc');
    expect(decision.allow).toBe(true);
    expect(decision.reason).toBe('denied_transient_error');
    expect(decision.errorCode).toBe('request_timeout');
  });

  it('always denies signature_invalid regardless of policy', async () => {
    const err = new MoltrustFirewallError('forged', 'signature_invalid');
    const gate = new EnforcementGate(clientThatThrows(err), { transientErrorPolicy: 'allow' });
    const decision = await gate.decide('did:moltrust:abc');
    expect(decision.allow).toBe(false);
    expect(decision.reason).toBe('denied_signature_invalid');
  });

  it('reports denied_unknown_error for non-MoltrustFirewallError causes', async () => {
    const gate = new EnforcementGate(clientThatThrows(new Error('random JS error')));
    const decision = await gate.decide('did:moltrust:abc');
    expect(decision.allow).toBe(false);
    expect(decision.reason).toBe('denied_unknown_error');
    expect(decision.errorCode).toBe('unknown');
  });

  it('honours an explicit deny on a DID', async () => {
    const gate = new EnforcementGate(clientThatThrows(new Error('unused')));
    gate.deny('did:moltrust:abc');
    const decision = await gate.decide('did:moltrust:abc');
    expect(decision.allow).toBe(false);
    expect(decision.reason).toBe('denied_revoked');
  });
});
