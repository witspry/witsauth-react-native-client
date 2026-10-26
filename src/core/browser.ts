import { BrowserSessionLauncher, BrowserSessionResult } from '../models/types';

/**
 * Creates a `BrowserSessionLauncher` using Expo's `expo-web-browser` module.
 */
export function createExpoWebBrowserLauncher(webBrowserModule: {
  openAuthSessionAsync: (url: string, redirectUrl?: string) => Promise<{ type: string; url?: string }>;
}): BrowserSessionLauncher {
  return async (authUrl: string, redirectUri: string): Promise<BrowserSessionResult> => {
    const result = await webBrowserModule.openAuthSessionAsync(authUrl, redirectUri);
    if (result.type === 'success' && result.url) {
      return { type: 'success', url: result.url };
    }
    if (result.type === 'cancel') {
      return { type: 'cancel' };
    }
    return { type: 'dismiss' };
  };
}

/**
 * Creates a `BrowserSessionLauncher` using `react-native-inappbrowser-reborn` for Bare React Native CLI apps.
 */
export function createInAppBrowserLauncher(inAppBrowserModule: {
  isAvailable: () => Promise<boolean>;
  openAuth: (
    url: string,
    redirectUrl: string,
    options?: Record<string, unknown>
  ) => Promise<{ type: string; url?: string }>;
}): BrowserSessionLauncher {
  return async (authUrl: string, redirectUri: string): Promise<BrowserSessionResult> => {
    const available = await inAppBrowserModule.isAvailable();
    if (!available) {
      throw new Error('InAppBrowser is not available on this device.');
    }
    const result = await inAppBrowserModule.openAuth(authUrl, redirectUri, {
      ephemeralWebSession: false,
      showTitle: false,
      enableUrlBarHiding: true,
      enableDefaultShare: false
    });
    if (result.type === 'success' && result.url) {
      return { type: 'success', url: result.url };
    }
    if (result.type === 'cancel') {
      return { type: 'cancel' };
    }
    return { type: 'dismiss' };
  };
}

/**
 * Parses `code`, `state`, `error`, and `error_description` from a custom-scheme or HTTPS callback URL.
 */
export function parseCallbackUrl(callbackUrl: string): {
  code: string | null;
  state: string | null;
  error: string | null;
  errorDescription: string | null;
} {
  const queryStart = callbackUrl.indexOf('?');
  if (queryStart === -1) {
    return { code: null, state: null, error: null, errorDescription: null };
  }
  const hashStart = callbackUrl.indexOf('#', queryStart);
  const queryString =
    hashStart === -1 ? callbackUrl.slice(queryStart + 1) : callbackUrl.slice(queryStart + 1, hashStart);
  const params = new URLSearchParams(queryString);
  return {
    code: params.get('code'),
    state: params.get('state'),
    error: params.get('error'),
    errorDescription: params.get('error_description')
  };
}
