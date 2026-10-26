import { OAuth2NativeConfig, STORAGE_KEYS, TokenInfo } from '../models/types';
import { createCodeChallenge, generateCodeVerifier, generateState } from './pkce';
import { NativeTokenStorage } from './storage';
import { parseCallbackUrl } from './browser';

export class AuthClient {
  private config: OAuth2NativeConfig;
  private storage: NativeTokenStorage;
  private refreshPromise: Promise<TokenInfo> | null = null;

  constructor(config: OAuth2NativeConfig, storage?: NativeTokenStorage) {
    this.config = config;
    this.storage = storage || new NativeTokenStorage(config.storage);
  }

  /**
   * Hydrates the in-memory token cache from the underlying async secure storage.
   * Called automatically by `AuthProvider` on mount.
   */
  async initialize(): Promise<void> {
    await this.storage.hydrate();
  }

  log(level: 'error' | 'warn' | 'info' | 'debug', ...args: unknown[]): void {
    const levels = { none: 0, error: 1, warn: 2, info: 3, debug: 4 };
    const currentLevel = levels[this.config.logLevel || 'warn'] || 0;
    const msgLevel = levels[level] || 0;

    if (msgLevel > 0 && currentLevel >= msgLevel) {
      console[level](...args);
    }
  }

  /**
   * Builds the OAuth 2.0 + PKCE authorization URL and persists `code_verifier`, `state`, and `nonce`.
   */
  async buildAuthorizationUrl(): Promise<string> {
    await this.storage.hydrate();

    const verifier = generateCodeVerifier();
    const challenge = await createCodeChallenge(verifier);
    const state = generateState();
    const nonce = this.config.nonce || generateState();

    await this.storage.setItem(STORAGE_KEYS.CODE_VERIFIER, verifier);
    await this.storage.setItem(STORAGE_KEYS.STATE, state);
    await this.storage.setItem(STORAGE_KEYS.NONCE, nonce);

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: this.config.responseType || 'code',
      code_challenge_method: this.config.codeChallengeMethod || 'S256',
      code_challenge: challenge,
      state,
      nonce
    });

    if (this.config.theme) {
      const themeVal = typeof this.config.theme === 'function' ? this.config.theme() : this.config.theme;
      if (themeVal) {
        params.append('theme', themeVal);
      }
    }

    if (this.config.scope) params.append('scope', this.config.scope);
    if (this.config.audience) params.append('audience', this.config.audience);

    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  /**
   * Launches the system authentication browser (`ASWebAuthenticationSession` on iOS / Chrome Custom Tabs on Android),
   * intercepts the deep-link callback (`redirectUri`), validates `state`, and exchanges `code` + `code_verifier` for tokens.
   */
  async authorize(): Promise<TokenInfo> {
    if (!this.config.openAuthSession) {
      throw new Error(
        'No openAuthSession launcher configured. Pass createExpoWebBrowserLauncher(WebBrowser) or createInAppBrowserLauncher(InAppBrowser) in OAuth2NativeConfig.'
      );
    }

    const authUrl = await this.buildAuthorizationUrl();
    const sessionResult = await this.config.openAuthSession(authUrl, this.config.redirectUri);

    if (sessionResult.type !== 'success' || !sessionResult.url) {
      await this.storage.clearTemporary();
      throw new Error(`Authentication ${sessionResult.type}`);
    }

    return this.handleCallbackUrl(sessionResult.url);
  }

  /**
   * Parses a redirect callback URL (`myapp://auth/callback?code=...&state=...`) and exchanges the code for tokens.
   */
  async handleCallbackUrl(callbackUrl: string): Promise<TokenInfo> {
    const { code, state, error, errorDescription } = parseCallbackUrl(callbackUrl);

    if (error) {
      await this.storage.clearTemporary();
      throw new Error(errorDescription ? `${error}: ${errorDescription}` : error);
    }

    if (!code || !state) {
      await this.storage.clearTemporary();
      throw new Error('Callback URL is missing required code or state parameters.');
    }

    return this.exchangeCodeForTokens(code, state);
  }

  async exchangeCodeForTokens(code: string, state: string): Promise<TokenInfo> {
    await this.storage.hydrate();

    const storedState = await this.storage.getItem(STORAGE_KEYS.STATE);
    const verifier = await this.storage.getItem(STORAGE_KEYS.CODE_VERIFIER);

    if (!storedState || state !== storedState) {
      await this.storage.clearTemporary();
      throw new Error('Invalid state parameter. Possible CSRF attack.');
    }
    if (!verifier) {
      await this.storage.clearTemporary();
      throw new Error('Code verifier missing from storage.');
    }

    const formData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      code,
      code_verifier: verifier
    });

    const response = await fetch(this.config.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString()
    });

    if (!response.ok) {
      throw new Error('Failed to exchange code for tokens');
    }

    const data = await response.json();

    const tokenInfo: TokenInfo = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      tokenType: data.token_type || 'Bearer',
      expiresAt: Date.now() + data.expires_in * 1000,
      scope: data.scope,
      idToken: data.id_token
    };

    await this.saveTokenInfo(tokenInfo);
    await this.storage.clearTemporary();

    return tokenInfo;
  }

  async refreshAccessToken(): Promise<TokenInfo> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = (async () => {
      await this.storage.hydrate();
      const refreshToken = await this.storage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      const formData = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.config.clientId,
        refresh_token: refreshToken
      });

      let response: Response;
      try {
        response = await fetch(this.config.tokenEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString()
        });
      } catch (networkError) {
        this.log('error', 'Token refresh network request failed:', networkError);
        throw networkError;
      }

      if (!response.ok) {
        let errorData: Record<string, string> = {};
        try {
          errorData = await response.json();
        } catch {
          try {
            errorData = { error: await response.text() };
          } catch {
            errorData = {};
          }
        }

        this.log('error', 'Token refresh failed with status:', response.status, errorData);

        if (response.status === 400 || response.status === 401) {
          await this.storage.clearTokens();
        }

        const errorMsg =
          errorData.error_description || errorData.error || response.statusText || 'Failed to refresh token';
        throw new Error(`Failed to refresh token (${response.status}): ${errorMsg}`);
      }

      const data = await response.json();

      const tokenInfo: TokenInfo = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || refreshToken,
        tokenType: data.token_type || 'Bearer',
        expiresAt: Date.now() + data.expires_in * 1000,
        scope: data.scope,
        idToken: data.id_token
      };

      await this.saveTokenInfo(tokenInfo);
      return tokenInfo;
    })().finally(() => {
      this.refreshPromise = null;
    });

    return this.refreshPromise;
  }

  private async saveTokenInfo(info: TokenInfo): Promise<void> {
    await this.storage.setItem(STORAGE_KEYS.ACCESS_TOKEN, info.accessToken);
    await this.storage.setItem(STORAGE_KEYS.TOKEN_EXPIRES_AT, info.expiresAt.toString());
    await this.storage.setItem(STORAGE_KEYS.TOKEN_TYPE, info.tokenType);
    if (info.refreshToken) {
      await this.storage.setItem(STORAGE_KEYS.REFRESH_TOKEN, info.refreshToken);
    }
    if (info.scope) {
      await this.storage.setItem(STORAGE_KEYS.SCOPE, info.scope);
    }
    if (info.idToken) {
      await this.storage.setItem(STORAGE_KEYS.ID_TOKEN, info.idToken);
    }
  }

  getAccessToken(): string | null {
    return this.storage.getItemSync(STORAGE_KEYS.ACCESS_TOKEN);
  }

  getRefreshToken(): string | null {
    return this.storage.getItemSync(STORAGE_KEYS.REFRESH_TOKEN);
  }

  getExpiresAt(): number | null {
    const expiresAt = this.storage.getItemSync(STORAGE_KEYS.TOKEN_EXPIRES_AT);
    if (!expiresAt) return null;
    const parsed = Number(expiresAt);
    return Number.isFinite(parsed) ? parsed : null;
  }

  isAuthenticated(): boolean {
    const expiresAt = this.getExpiresAt();
    if (expiresAt === null) return false;
    const isValid = Date.now() < expiresAt - 30000;
    return isValid && !!this.getAccessToken();
  }

  /**
   * Opens the hosted WitsAuth Account Management portal (`/auth/account`) in the native secure browser
   * using a short-lived single-use ticket (`POST /auth/account/ticket`), allowing the user to change
   * their password, update their profile, or verify their mobile phone number via OTP.
   */
  async navigateToAccountManagement(): Promise<void> {
    await this.storage.hydrate();
    const refreshToken = await this.storage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
    if (!refreshToken) {
      throw new Error('No refresh token available to access account management.');
    }

    if (!this.config.openAuthSession) {
      throw new Error(
        'No openAuthSession launcher configured. Pass createExpoWebBrowserLauncher(WebBrowser) or createInAppBrowserLauncher(InAppBrowser) in OAuth2NativeConfig.'
      );
    }

    const authEndpointBase = this.config.authorizationEndpoint.replace(/\/authorize\/?$/, '');
    const ticketResponse = await fetch(`${authEndpointBase}/account/ticket`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        refreshToken,
        clientId: this.config.clientId,
        redirectUri: this.config.redirectUri
      })
    });

    if (!ticketResponse.ok) {
      throw new Error(`Failed to request account management ticket (${ticketResponse.status})`);
    }

    const { ticket } = await ticketResponse.json();
    if (!ticket) {
      throw new Error('Account management ticket missing from server response.');
    }

    const accountUrl = `${authEndpointBase}/account?ticket=${encodeURIComponent(ticket)}&return_to=${encodeURIComponent(this.config.redirectUri)}`;
    await this.config.openAuthSession(accountUrl, this.config.redirectUri);
  }

  /**
   * Clears tokens from secure storage and revokes both refresh_token and access_token at `revokeEndpoint`.
   */
  async logout(): Promise<void> {
    await this.storage.hydrate();
    const accessToken = this.getAccessToken();
    const refreshToken = await this.storage.getItem(STORAGE_KEYS.REFRESH_TOKEN);

    await this.storage.clearTokens();
    await this.storage.clearTemporary();

    if (this.config.revokeEndpoint) {
      const tokensToRevoke = [
        ...(refreshToken ? [{ token: refreshToken, token_type_hint: 'refresh_token' }] : []),
        ...(accessToken ? [{ token: accessToken, token_type_hint: 'access_token' }] : [])
      ];

      for (const item of tokensToRevoke) {
        try {
          await fetch(this.config.revokeEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              token: item.token,
              token_type_hint: item.token_type_hint,
              client_id: this.config.clientId
            }).toString()
          });
        } catch (err) {
          this.log('error', 'Failed to revoke token during logout', err);
        }
      }
    }
  }
}
