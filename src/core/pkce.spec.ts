import { describe, it, expect } from 'vitest';
import {
  generateCodeVerifier,
  generateState,
  createCodeChallenge,
  sha256Bytes,
  base64UrlEncode
} from './pkce';

describe('PKCE Utilities (Hermes-Compatible S256)', () => {
  it('generates a valid RFC 7636 code verifier of length 64', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toHaveLength(64);
    expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it('generates a valid state string of length 32', () => {
    const state = generateState();
    expect(state).toHaveLength(32);
    expect(state).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it('produces the exact RFC 7636 Appendix B S256 code challenge via pure-TS SHA-256', async () => {
    // RFC 7636 Appendix B test vector:
    // verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // expected S256 challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    const rfcVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const expectedChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    const pureTsChallenge = base64UrlEncode(sha256Bytes(rfcVerifier));
    expect(pureTsChallenge).toBe(expectedChallenge);

    const asyncChallenge = await createCodeChallenge(rfcVerifier);
    expect(asyncChallenge).toBe(expectedChallenge);
  });

  it('throws a descriptive security error if CSPRNG is unavailable instead of falling back to Math.random()', () => {
    const originalCrypto = globalThis.crypto;
    try {
      Object.defineProperty(globalThis, 'crypto', {
        value: undefined,
        configurable: true
      });
      expect(() => generateCodeVerifier()).toThrow(/Cryptographically secure random number generator/);
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        value: originalCrypto,
        configurable: true
      });
    }
  });
});
