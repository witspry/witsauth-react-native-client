import { OAuth2AsyncStorage, STORAGE_KEYS } from '../models/types';

const ALL_STORAGE_KEYS = Object.values(STORAGE_KEYS);

/**
 * Wraps an asynchronous native secure store (e.g., Expo SecureStore or React Native Keychain)
 * with a synchronous in-memory read cache. Once `hydrate()` resolves on startup,
 * `getAccessToken()` and `isAuthenticated()` are synchronous while all mutations
 * persist asynchronously to the native keychain/keystore.
 */
export class NativeTokenStorage {
  private backend: OAuth2AsyncStorage;
  private cache: Map<string, string> = new Map();
  private hydrated = false;
  private hydratePromise: Promise<void> | null = null;

  constructor(customStorage?: OAuth2AsyncStorage) {
    this.backend = customStorage || createMemoryStorageAdapter();
  }

  async hydrate(): Promise<void> {
    if (this.hydrated) return;
    if (this.hydratePromise) return this.hydratePromise;

    this.hydratePromise = (async () => {
      await Promise.all(
        ALL_STORAGE_KEYS.map(async (key) => {
          try {
            const val = await this.backend.getItem(key);
            if (val !== null && val !== undefined) {
              this.cache.set(key, val);
            }
          } catch {
            // Ignore single-key read failure during hydration
          }
        })
      );
      this.hydrated = true;
    })().finally(() => {
      this.hydratePromise = null;
    });

    return this.hydratePromise;
  }

  getItemSync(key: string): string | null {
    return this.cache.get(key) ?? null;
  }

  async getItem(key: string): Promise<string | null> {
    if (this.cache.has(key)) {
      return this.cache.get(key)!;
    }
    const val = await this.backend.getItem(key);
    if (val !== null && val !== undefined) {
      this.cache.set(key, val);
      return val;
    }
    return null;
  }

  async setItem(key: string, value: string): Promise<void> {
    this.cache.set(key, value);
    await this.backend.setItem(key, value);
  }

  async removeItem(key: string): Promise<void> {
    this.cache.delete(key);
    await this.backend.removeItem(key);
  }

  async clearTemporary(): Promise<void> {
    await Promise.all([
      this.removeItem(STORAGE_KEYS.CODE_VERIFIER),
      this.removeItem(STORAGE_KEYS.STATE),
      this.removeItem(STORAGE_KEYS.NONCE)
    ]);
  }

  async clearTokens(): Promise<void> {
    await Promise.all([
      this.removeItem(STORAGE_KEYS.ACCESS_TOKEN),
      this.removeItem(STORAGE_KEYS.REFRESH_TOKEN),
      this.removeItem(STORAGE_KEYS.TOKEN_EXPIRES_AT),
      this.removeItem(STORAGE_KEYS.TOKEN_TYPE),
      this.removeItem(STORAGE_KEYS.SCOPE),
      this.removeItem(STORAGE_KEYS.ID_TOKEN)
    ]);
  }
}

export function createMemoryStorageAdapter(): OAuth2AsyncStorage {
  const store = new Map<string, string>();
  return {
    getItem: async (key: string) => store.get(key) ?? null,
    setItem: async (key: string, value: string) => {
      store.set(key, value);
    },
    removeItem: async (key: string) => {
      store.delete(key);
    }
  };
}

const EXPO_SECURE_STORE_CHUNK_SIZE = 2000;
const CHUNK_MANIFEST_PREFIX = '__witsauth_chunked__:';

/**
 * Helper to create a storage adapter backed by `expo-secure-store`.
 * Automatically splits values exceeding 2000 bytes across indexed chunk keys
 * to prevent Expo SecureStore's 2048-byte limit errors on large JWTs.
 * Pass the imported `SecureStore` module from `expo-secure-store`.
 */
export function createExpoSecureStoreAdapter(secureStoreModule: {
  getItemAsync: (key: string) => Promise<string | null>;
  setItemAsync: (key: string, value: string) => Promise<void>;
  deleteItemAsync: (key: string) => Promise<void>;
}): OAuth2AsyncStorage {
  const deleteChunksIfPresent = async (key: string): Promise<void> => {
    try {
      const existing = await secureStoreModule.getItemAsync(key);
      if (existing && existing.startsWith(CHUNK_MANIFEST_PREFIX)) {
        const count = parseInt(existing.slice(CHUNK_MANIFEST_PREFIX.length), 10);
        if (Number.isFinite(count) && count > 0) {
          const deletions: Promise<void>[] = [];
          for (let i = 0; i < count; i++) {
            deletions.push(secureStoreModule.deleteItemAsync(`${key}__chunk_${i}`));
          }
          await Promise.all(deletions);
        }
      }
    } catch {
      // Ignore cleanup read errors
    }
  };

  return {
    getItem: async (key: string) => {
      const raw = await secureStoreModule.getItemAsync(key);
      if (!raw) return null;
      if (raw.startsWith(CHUNK_MANIFEST_PREFIX)) {
        const count = parseInt(raw.slice(CHUNK_MANIFEST_PREFIX.length), 10);
        if (!Number.isFinite(count) || count <= 0) return null;
        const chunkPromises: Promise<string | null>[] = [];
        for (let i = 0; i < count; i++) {
          chunkPromises.push(secureStoreModule.getItemAsync(`${key}__chunk_${i}`));
        }
        const chunks = await Promise.all(chunkPromises);
        if (chunks.some((c) => c === null || c === undefined)) {
          return null;
        }
        return chunks.join('');
      }
      return raw;
    },
    setItem: async (key: string, value: string) => {
      if (value.length <= EXPO_SECURE_STORE_CHUNK_SIZE) {
        await deleteChunksIfPresent(key);
        await secureStoreModule.setItemAsync(key, value);
        return;
      }

      await deleteChunksIfPresent(key);
      const chunks: string[] = [];
      for (let offset = 0; offset < value.length; offset += EXPO_SECURE_STORE_CHUNK_SIZE) {
        chunks.push(value.slice(offset, offset + EXPO_SECURE_STORE_CHUNK_SIZE));
      }

      await Promise.all(
        chunks.map((chunk, index) => secureStoreModule.setItemAsync(`${key}__chunk_${index}`, chunk))
      );
      await secureStoreModule.setItemAsync(key, `${CHUNK_MANIFEST_PREFIX}${chunks.length}`);
    },
    removeItem: async (key: string) => {
      await deleteChunksIfPresent(key);
      await secureStoreModule.deleteItemAsync(key);
    }
  };
}

/**
 * Helper to create a storage adapter backed by `react-native-keychain` for Bare React Native CLI apps.
 * Pass the imported `Keychain` module from `react-native-keychain`.
 */
export function createKeychainStorageAdapter(
  keychainModule: {
    getGenericPassword: (options?: { service?: string }) => Promise< false | { username: string; password: string } >;
    setGenericPassword: (username: string, password: string, options?: { service?: string }) => Promise<unknown>;
    resetGenericPassword: (options?: { service?: string }) => Promise<unknown>;
  },
  servicePrefix: string = 'com.witsauth.tokens'
): OAuth2AsyncStorage {
  return {
    getItem: async (key: string) => {
      const creds = await keychainModule.getGenericPassword({ service: `${servicePrefix}.${key}` });
      return creds ? creds.password : null;
    },
    setItem: async (key: string, value: string) => {
      await keychainModule.setGenericPassword(key, value, { service: `${servicePrefix}.${key}` });
    },
    removeItem: async (key: string) => {
      await keychainModule.resetGenericPassword({ service: `${servicePrefix}.${key}` });
    }
  };
}
