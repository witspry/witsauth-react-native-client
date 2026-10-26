export interface OAuth2AsyncStorage {
  getItem(key: string): Promise<string | null> | string | null;
  setItem(key: string, value: string): Promise<void> | void;
  removeItem(key: string): Promise<void> | void;
}

export interface BrowserSessionResult {
  type: 'success' | 'cancel' | 'dismiss';
  url?: string;
}

export type BrowserSessionLauncher = (
  authUrl: string,
  redirectUri: string
) => Promise<BrowserSessionResult>;

export interface OAuth2NativeConfig {
  /**
   * The Client ID obtained from the WitsAuth console.
   */
  clientId: string;

  /**
   * The authorization endpoint URL.
   * E.g., https://auth.example.com/auth/authorize
   */
  authorizationEndpoint: string;

  /**
   * The token endpoint URL.
   * E.g., https://auth.example.com/oauth/token
   */
  tokenEndpoint: string;

  /**
   * The callback URI configured for your mobile application.
   * Supports custom schemes (e.g., myapp://auth/callback) and Universal/App Links.
   */
  redirectUri: string;

  /**
   * Optional userInfo endpoint URL.
   * E.g., https://auth.example.com/oauth/userinfo
   */
  userInfoEndpoint?: string;

  /**
   * Optional token revocation endpoint URL.
   * E.g., https://auth.example.com/oauth/revoke
   */
  revokeEndpoint?: string;

  /**
   * Optional logout endpoint URL.
   * E.g., https://auth.example.com/auth/logout
   */
  logoutEndpoint?: string;

  /**
   * Scopes to request, separated by spaces.
   * E.g., "openid profile email offline_access"
   */
  scope?: string;

  /**
   * Audience parameter to request (if required by WitsAuth).
   */
  audience?: string;

  /**
   * Optional static nonce value. If omitted, a random cryptographic nonce is generated per authorization request.
   */
  nonce?: string;

  /**
   * Optional theme hint ("light" | "dark") or a callback returning the current theme.
   */
  theme?: 'light' | 'dark' | (() => 'light' | 'dark' | undefined);

  /**
   * Response type. Defaults to "code".
   */
  responseType?: string;

  /**
   * PKCE code challenge method. Defaults to "S256".
   */
  codeChallengeMethod?: 'S256' | 'plain';

  /**
   * Secure async storage adapter (e.g., Expo SecureStore or React Native Keychain).
   * If omitted, falls back to an in-memory store.
   */
  storage?: OAuth2AsyncStorage;

  /**
   * Custom system browser session launcher (ASWebAuthenticationSession on iOS / Chrome Custom Tabs on Android).
   * If omitted, auto-detects `expo-web-browser` or `react-native-inappbrowser-reborn`.
   */
  openAuthSession?: BrowserSessionLauncher;

  /**
   * Log level for internal client messages. Defaults to 'warn'.
   */
  logLevel?: 'none' | 'error' | 'warn' | 'info' | 'debug';
}

export interface TokenInfo {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number; // Timestamp in ms
  tokenType: string;
  scope?: string;
  idToken?: string;
}

export const STORAGE_KEYS = {
  ACCESS_TOKEN: 'witsauth_access_token',
  REFRESH_TOKEN: 'witsauth_refresh_token',
  TOKEN_EXPIRES_AT: 'witsauth_expires_at',
  TOKEN_TYPE: 'witsauth_token_type',
  SCOPE: 'witsauth_scope',
  ID_TOKEN: 'witsauth_id_token',
  CODE_VERIFIER: 'witsauth_code_verifier',
  STATE: 'witsauth_state',
  NONCE: 'witsauth_nonce'
} as const;
