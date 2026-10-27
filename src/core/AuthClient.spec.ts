import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthClient } from './AuthClient';
import { createExpoSecureStoreAdapter, createMemoryStorageAdapter } from './storage';
import { BrowserSessionLauncher, OAuth2NativeConfig, STORAGE_KEYS } from '../models/types';
import { base64UrlEncode } from './pkce';

describe('AuthClient (@witsauth/react-native-client)', () => {
  let memoryStorage: ReturnType<typeof createMemoryStorageAdapter>;
  let mockOpenAuthSession: ReturnType<typeof vi.fn<BrowserSessionLauncher>>;
  let config: OAuth2NativeConfig;

  beforeEach(() => {
    memoryStorage = createMemoryStorageAdapter();
    mockOpenAuthSession = vi.fn<BrowserSessionLauncher>();
    config = {
      clientId: 'rn-mobile-client',
      authorizationEndpoint: 'https://auth.witspry.com/auth/authorize',
      tokenEndpoint: 'https://auth.witspry.com/oauth/token',
      revokeEndpoint: 'https://auth.witspry.com/oauth/revoke',
      redirectUri: 'myapp://auth/callback',
      scope: 'openid profile email offline_access',
      storage: memoryStorage,
      openAuthSession: mockOpenAuthSession
    };
    vi.restoreAllMocks();
  });

  it('completes OAuth 2.0 + PKCE authorize() flow via system browser and deep-link callback', async () => {
    mockOpenAuthSession.mockImplementation(async (authUrl: string) => {
      const parsed = new URL(authUrl);
      const state = parsed.searchParams.get('state');
      expect(parsed.searchParams.get('client_id')).toBe('rn-mobile-client');
      expect(parsed.searchParams.get('redirect_uri')).toBe('myapp://auth/callback');
      expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
      expect(parsed.searchParams.get('code_challenge')).toBeTruthy();

      return {
        type: 'success',
        url: `myapp://auth/callback?code=auth-code-xyz&state=${state}`
      };
    });

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'access-123',
          refresh_token: 'refresh-456',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'openid profile email offline_access'
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const client = new AuthClient(config);
    const tokenInfo = await client.authorize();

    expect(tokenInfo.accessToken).toBe('access-123');
    expect(tokenInfo.refreshToken).toBe('refresh-456');
    expect(client.isAuthenticated()).toBe(true);
    expect(client.getAccessToken()).toBe('access-123');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('rejects callback URL when state does not match stored state (CSRF protection)', async () => {
    mockOpenAuthSession.mockResolvedValue({
      type: 'success',
      url: 'myapp://auth/callback?code=auth-code-xyz&state=tampered-state'
    });

    const client = new AuthClient(config);
    await expect(client.authorize()).rejects.toThrow(/Invalid state parameter/);
  });

  it('deduplicates concurrent refreshAccessToken() calls', async () => {
    await memoryStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, 'initial-refresh-token');

    let resolveFetch!: (value: Response) => void;
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        })
    );

    const client = new AuthClient(config);
    const p1 = client.refreshAccessToken();
    const p2 = client.refreshAccessToken();

    await vi.waitFor(() => {
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });

    resolveFetch(
      new Response(
        JSON.stringify({
          access_token: 'new-access-token',
          refresh_token: 'rotated-refresh-token',
          token_type: 'Bearer',
          expires_in: 3600
        }),
        { status: 200 }
      )
    );

    const [res1, res2] = await Promise.all([p1, p2]);
    expect(res1.accessToken).toBe('new-access-token');
    expect(res2.accessToken).toBe('new-access-token');
    expect(client.getRefreshToken()).toBe('rotated-refresh-token');
  });

  it('opens Account Management using a single-use ticket from POST /auth/account/ticket', async () => {
    await memoryStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, 'active-refresh-token');
    mockOpenAuthSession.mockResolvedValue({ type: 'dismiss' });

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ ticket: 'one-time-ticket-999' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      })
    );

    const client = new AuthClient(config);
    await client.navigateToAccountManagement();

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://auth.witspry.com/auth/account/ticket',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          refreshToken: 'active-refresh-token',
          clientId: 'rn-mobile-client',
          redirectUri: 'myapp://auth/callback'
        })
      })
    );

    expect(mockOpenAuthSession).toHaveBeenCalledWith(
      'https://auth.witspry.com/auth/account?ticket=one-time-ticket-999&return_to=myapp%3A%2F%2Fauth%2Fcallback',
      'myapp://auth/callback'
    );
  });

  it('revokes both refresh_token and access_token with client_id on logout()', async () => {
    await memoryStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, 'acc-token-1');
    await memoryStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, 'ref-token-1');
    await memoryStorage.setItem(STORAGE_KEYS.TOKEN_EXPIRES_AT, String(Date.now() + 3600000));

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 200 }));

    const client = new AuthClient(config);
    await client.logout();

    expect(client.getAccessToken()).toBeNull();
    expect(client.getRefreshToken()).toBeNull();
    expect(fetchSpy).toHaveBeenCalledTimes(2);

    const firstCallBody = fetchSpy.mock.calls[0][1]?.body as string;
    expect(firstCallBody).toContain('token=ref-token-1');
    expect(firstCallBody).toContain('token_type_hint=refresh_token');
    expect(firstCallBody).toContain('client_id=rn-mobile-client');
  });

  it('exposes getIdToken() and getUserProfile() from decoded ID token claims', async () => {
    const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
    const payloadObj = {
      sub: 'usr_12345',
      email: 'mobile@example.com',
      phone_number: '+14155552671',
      phone_number_verified: true,
      amr: ['sms', 'otp']
    };
    const payload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payloadObj)));
    const fakeIdToken = `${header}.${payload}.sig`;

    await memoryStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, 'acc-token-1');
    await memoryStorage.setItem(STORAGE_KEYS.ID_TOKEN, fakeIdToken);
    await memoryStorage.setItem(STORAGE_KEYS.TOKEN_EXPIRES_AT, String(Date.now() + 3600000));

    const client = new AuthClient(config);
    await client.initialize();

    expect(client.getIdToken()).toBe(fakeIdToken);
    expect(client.getUserProfile()).toEqual(payloadObj);
  });

  it('supports prompt parameter in buildAuthorizationUrl() and authorize()', async () => {
    const client = new AuthClient(config);
    const url = await client.buildAuthorizationUrl({ prompt: 'select_account' });
    const parsed = new URL(url);
    expect(parsed.searchParams.get('prompt')).toBe('select_account');
  });

  it('launches logoutEndpoint in system browser when logout({ clearBrowserSession: true }) is called', async () => {
    config.logoutEndpoint = 'https://auth.witspry.com/auth/logout';
    mockOpenAuthSession.mockResolvedValue({ type: 'dismiss' });
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 200 }));

    const client = new AuthClient(config);
    await client.logout({ clearBrowserSession: true });

    expect(mockOpenAuthSession).toHaveBeenCalledWith(
      'https://auth.witspry.com/auth/logout?client_id=rn-mobile-client&redirect_uri=myapp%3A%2F%2Fauth%2Fcallback',
      'myapp://auth/callback'
    );
  });

  it('transparently chunks and reassembles values > 2000 bytes in createExpoSecureStoreAdapter()', async () => {
    const backingStore = new Map<string, string>();
    const adapter = createExpoSecureStoreAdapter({
      getItemAsync: async (k) => backingStore.get(k) ?? null,
      setItemAsync: async (k, v) => {
        if (v.length > 2048) {
          throw new Error('Value exceeds Expo SecureStore 2048 byte limit');
        }
        backingStore.set(k, v);
      },
      deleteItemAsync: async (k) => {
        backingStore.delete(k);
      }
    });

    const largeJwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.' + 'a'.repeat(4500) + '.signature';
    await adapter.setItem(STORAGE_KEYS.ACCESS_TOKEN, largeJwt);

    expect(backingStore.get(STORAGE_KEYS.ACCESS_TOKEN)).toBe('__witsauth_chunked__:3');
    const retrieved = await adapter.getItem(STORAGE_KEYS.ACCESS_TOKEN);
    expect(retrieved).toBe(largeJwt);

    await adapter.removeItem(STORAGE_KEYS.ACCESS_TOKEN);
    expect(await adapter.getItem(STORAGE_KEYS.ACCESS_TOKEN)).toBeNull();
    expect(backingStore.size).toBe(0);
  });
});
