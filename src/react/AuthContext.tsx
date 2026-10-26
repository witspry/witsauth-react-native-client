import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { AuthClient } from '../core/AuthClient';
import { OAuth2NativeConfig } from '../models/types';

export interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  accessToken: string | null;
  error: Error | null;
  login: () => Promise<void>;
  logout: () => Promise<void>;
  getToken: () => Promise<string | null>;
  navigateToAccountManagement: () => Promise<void>;
  authClient: AuthClient;
}

const AuthContext = createContext<AuthContextType | null>(null);

export interface AuthProviderProps {
  config?: OAuth2NativeConfig;
  client?: AuthClient;
  children: React.ReactNode;
  onLoginSuccess?: () => void;
  onLoginError?: (error: Error) => void;
  /**
   * Optional subscription to React Native's `AppState.addEventListener('change', listener)`
   * so tokens automatically refresh when the app returns to the foreground (`active`).
   */
  subscribeAppState?: (listener: (state: string) => void) => () => void;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({
  config,
  client,
  children,
  onLoginSuccess,
  onLoginError,
  subscribeAppState
}) => {
  const [authClient] = useState<AuthClient>(() => {
    if (client) return client;
    if (config) return new AuthClient(config);
    throw new Error('AuthProvider requires either a `client` or `config` prop.');
  });

  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<Error | null>(null);

  const syncAuthState = useCallback(async (): Promise<void> => {
    await authClient.initialize();
    if (authClient.isAuthenticated()) {
      setIsAuthenticated(true);
      setAccessToken(authClient.getAccessToken());
      return;
    }

    if (authClient.getRefreshToken()) {
      try {
        const tokenInfo = await authClient.refreshAccessToken();
        setIsAuthenticated(true);
        setAccessToken(tokenInfo.accessToken);
        return;
      } catch {
        setIsAuthenticated(false);
        setAccessToken(null);
        return;
      }
    }

    setIsAuthenticated(false);
    setAccessToken(null);
  }, [authClient]);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        await syncAuthState();
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    })();
    return () => {
      mounted = false;
    };
  }, [syncAuthState]);

  // Foreground + timer-based proactive token refresh
  useEffect(() => {
    if (!isAuthenticated) return;

    let timeoutId: ReturnType<typeof setTimeout>;
    const scheduleRefresh = () => {
      const expiresAt = authClient.getExpiresAt();
      if (!expiresAt) return;

      const timeUntilRefresh = expiresAt - Date.now() - 60000;
      const delay = Math.max(0, timeUntilRefresh);

      timeoutId = setTimeout(async () => {
        try {
          const tokenInfo = await authClient.refreshAccessToken();
          setAccessToken(tokenInfo.accessToken);
          setIsAuthenticated(true);
          scheduleRefresh();
        } catch (err) {
          authClient.log('error', 'Background token refresh failed:', err);
          if (!authClient.getAccessToken()) {
            setIsAuthenticated(false);
            setAccessToken(null);
          } else {
            timeoutId = setTimeout(scheduleRefresh, 30000);
          }
        }
      }, delay);
    };

    scheduleRefresh();

    const unsubscribeAppState = subscribeAppState
      ? subscribeAppState((nextState) => {
          if (nextState === 'active') {
            syncAuthState().catch(() => {});
          }
        })
      : undefined;

    return () => {
      if (timeoutId) clearTimeout(timeoutId);
      if (unsubscribeAppState) unsubscribeAppState();
    };
  }, [isAuthenticated, authClient, subscribeAppState, syncAuthState]);

  const login = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const tokenInfo = await authClient.authorize();
      setAccessToken(tokenInfo.accessToken);
      setIsAuthenticated(true);
      onLoginSuccess?.();
    } catch (err) {
      const authErr = err instanceof Error ? err : new Error('Authentication failed');
      setError(authErr);
      onLoginError?.(authErr);
    } finally {
      setIsLoading(false);
    }
  }, [authClient, onLoginSuccess, onLoginError]);

  const logout = useCallback(async () => {
    setIsLoading(true);
    try {
      await authClient.logout();
      setIsAuthenticated(false);
      setAccessToken(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Logout failed'));
    } finally {
      setIsLoading(false);
    }
  }, [authClient]);

  const getToken = useCallback(async (): Promise<string | null> => {
    await authClient.initialize();
    if (authClient.isAuthenticated()) {
      return authClient.getAccessToken();
    }
    try {
      const info = await authClient.refreshAccessToken();
      setAccessToken(info.accessToken);
      setIsAuthenticated(true);
      return info.accessToken;
    } catch {
      setIsAuthenticated(false);
      setAccessToken(null);
      return null;
    }
  }, [authClient]);

  const navigateToAccountManagement = useCallback(async () => {
    await authClient.navigateToAccountManagement();
    // Re-sync auth state after user returns from Account Management (e.g. if password changed)
    await syncAuthState();
  }, [authClient, syncAuthState]);

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        isLoading,
        accessToken,
        error,
        login,
        logout,
        getToken,
        navigateToAccountManagement,
        authClient
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
