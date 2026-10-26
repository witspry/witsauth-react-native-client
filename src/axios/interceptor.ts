import { AxiosInstance, InternalAxiosRequestConfig, AxiosError } from 'axios';
import { AuthClient } from '../core/AuthClient';

interface FailedRequest {
  resolve: (token: string | null) => void;
  reject: (error: unknown) => void;
}

export interface InterceptorOptions {
  /**
   * Optional callback triggered when token refresh fails completely (e.g., refresh token expired).
   */
  onUnauthorized?: () => void;
  /**
   * Specify URLs that should NOT have the Authorization header injected.
   */
  excludeUrls?: (string | RegExp)[];
}

export function setupAxiosInterceptors(
  axiosInstance: AxiosInstance,
  authClient: AuthClient,
  options: InterceptorOptions = {}
): () => void {
  let isRefreshing = false;
  let failedQueue: FailedRequest[] = [];

  const processQueue = (error: unknown, token: string | null = null) => {
    failedQueue.forEach((prom) => {
      if (error) {
        prom.reject(error);
      } else {
        prom.resolve(token);
      }
    });
    failedQueue = [];
  };

  const isExcluded = (url?: string): boolean => {
    if (!url || !options.excludeUrls) return false;
    return options.excludeUrls.some((pattern) => {
      if (typeof pattern === 'string') {
        return url.includes(pattern);
      }
      return pattern.test(url);
    });
  };

  const requestInterceptor = axiosInstance.interceptors.request.use(
    async (config: InternalAxiosRequestConfig) => {
      if (isExcluded(config.url)) {
        return config;
      }

      await authClient.initialize();
      let token = authClient.getAccessToken();

      if (!authClient.isAuthenticated() && token) {
        try {
          const newInfo = await authClient.refreshAccessToken();
          token = newInfo.accessToken;
        } catch {
          token = null;
        }
      }

      if (token) {
        config.headers.set('Authorization', `Bearer ${token}`);
      }

      return config;
    },
    (error: unknown) => Promise.reject(error)
  );

  const responseInterceptor = axiosInstance.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

      if (!originalRequest || isExcluded(originalRequest.url)) {
        return Promise.reject(error);
      }

      if (error.response?.status === 401 && !originalRequest._retry) {
        if (isRefreshing) {
          return new Promise<string | null>((resolve, reject) => {
            failedQueue.push({ resolve, reject });
          })
            .then((token) => {
              if (token) {
                originalRequest.headers.set('Authorization', `Bearer ${token}`);
              }
              return axiosInstance(originalRequest);
            })
            .catch((err) => Promise.reject(err));
        }

        originalRequest._retry = true;
        isRefreshing = true;

        try {
          const tokenInfo = await authClient.refreshAccessToken();
          const newToken = tokenInfo.accessToken;

          processQueue(null, newToken);
          originalRequest.headers.set('Authorization', `Bearer ${newToken}`);
          return axiosInstance(originalRequest);
        } catch (refreshError) {
          processQueue(refreshError, null);
          await authClient.logout();

          if (options.onUnauthorized) {
            options.onUnauthorized();
          }

          return Promise.reject(refreshError);
        } finally {
          isRefreshing = false;
        }
      }

      return Promise.reject(error);
    }
  );

  return () => {
    axiosInstance.interceptors.request.eject(requestInterceptor);
    axiosInstance.interceptors.response.eject(responseInterceptor);
  };
}
