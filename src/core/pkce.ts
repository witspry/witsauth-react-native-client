/**
 * Hermes-compatible PKCE (RFC 7636) utilities.
 * Uses Web Crypto API when available, and falls back to a pure-TypeScript
 * FIPS 180-4 SHA-256 implementation so S256 works out-of-the-box on React Native
 * Hermes without requiring native crypto polyfills.
 */

const BASE64URL_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rotr(n: number, x: number): number {
  return (x >>> n) | (x << (32 - n));
}

function utf8ToBytes(str: string): Uint8Array {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(str);
  }
  const bytes: number[] = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0xd800 || code >= 0xe000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      i++;
      code = 0x10000 + (((code & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      bytes.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f)
      );
    }
  }
  return new Uint8Array(bytes);
}

/**
 * Pure-TypeScript FIPS 180-4 SHA-256 digest.
 */
export function sha256Bytes(asciiOrUtf8: string): Uint8Array {
  const msg = utf8ToBytes(asciiOrUtf8);
  const bitLen = msg.length * 8;

  const paddedLen = ((msg.length + 9 + 63) >> 6) << 6;
  const padded = new Uint8Array(paddedLen);
  padded.set(msg);
  padded[msg.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(paddedLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
      const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  outView.setUint32(20, h5, false);
  outView.setUint32(24, h6, false);
  outView.setUint32(28, h7, false);
  return out;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;

    result += BASE64URL_CHARSET[b0 >> 2];
    result += BASE64URL_CHARSET[((b0 & 0x03) << 4) | (b1 >> 4)];
    if (i + 1 < len) {
      result += BASE64URL_CHARSET[((b1 & 0x0f) << 2) | (b2 >> 6)];
    }
    if (i + 2 < len) {
      result += BASE64URL_CHARSET[b2 & 0x3f];
    }
  }
  return result;
}

export function getRandomBytes(length: number): Uint8Array {
  const array = new Uint8Array(length);
  const g = typeof globalThis !== 'undefined' ? (globalThis as any) : undefined;
  if (g?.crypto && typeof g.crypto.getRandomValues === 'function') {
    g.crypto.getRandomValues(array);
    return array;
  }

  try {
    const req = typeof g?.require === 'function' ? g.require : undefined;
    if (req) {
      const expoCrypto = req('expo-crypto');
      if (expoCrypto && typeof expoCrypto.getRandomValues === 'function') {
        expoCrypto.getRandomValues(array);
        return array;
      }
      if (expoCrypto && typeof expoCrypto.getRandomBytes === 'function') {
        const bytes: Uint8Array = expoCrypto.getRandomBytes(length);
        array.set(bytes.subarray(0, length));
        return array;
      }
    }
  } catch {
    // expo-crypto not installed
  }

  throw new Error(
    'Cryptographically secure random number generator (CSPRNG) is unavailable. Please install and import "react-native-get-random-values" or "expo-crypto".'
  );
}

function base64UrlDecodeToUtf8(input: string): string {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);

  if (typeof atob === 'function') {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder().decode(bytes);
    }
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      out += String.fromCharCode(bytes[i]);
    }
    return decodeURIComponent(escape(out));
  }

  const g = typeof globalThis !== 'undefined' ? (globalThis as any) : undefined;
  if (g?.Buffer) {
    return g.Buffer.from(padded, 'base64').toString('utf8');
  }

  throw new Error('Unable to decode base64url string.');
}

export function decodeJwtPayload<T = Record<string, unknown>>(token: string | null | undefined): T | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const json = base64UrlDecodeToUtf8(parts[1]);
    return JSON.parse(json) as T;
  } catch {
    return null;
  }
}

export function generateRandomString(length: number = 64): string {
  const validChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const randomBytes = getRandomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += validChars[randomBytes[i] % validChars.length];
  }
  return result;
}

export function generateCodeVerifier(): string {
  return generateRandomString(64);
}

export function generateState(): string {
  return generateRandomString(32);
}

export async function createCodeChallenge(verifier: string): Promise<string> {
  const g = typeof globalThis !== 'undefined' ? (globalThis as any) : undefined;
  if (g?.crypto?.subtle && typeof g.crypto.subtle.digest === 'function') {
    try {
      const data = utf8ToBytes(verifier);
      const digest = await g.crypto.subtle.digest('SHA-256', data);
      return base64UrlEncode(new Uint8Array(digest));
    } catch {
      // Fallback to pure-TS SHA-256
    }
  }
  return base64UrlEncode(sha256Bytes(verifier));
}
