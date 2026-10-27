# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2026-10-27

### Added
- Added RFC 8693 Impersonation Actor (`act`) claim inspection via `getImpersonationActor()` and `isImpersonatedSession()` on `AuthClient` and the `useAuth()` hook (`impersonationActor` and `isImpersonated`).
- Added automatic chunked persistence across 2,000-byte segments in `createExpoSecureStoreAdapter()` (`__chunks` index + `__chunk_N` keys) so large JWTs with rich `scope` and `roles` payloads never fail iOS/Android `expo-secure-store` size limits.
- Added React Native deep-link listener wiring (`Linking.getInitialURL()` + `Linking.addEventListener('url', ...)` or custom `subscribeDeepLinks` prop) inside `AuthProvider` to automatically intercept `redirectUri` OAuth callbacks when Android OS kills/recreates `MainActivity` while the browser tab is open.
- Added multi-tier CSPRNG fallback in `getRandomBytes()` (`globalThis.crypto.getRandomValues` -> `expo-crypto` -> `react-native-get-random-values` -> throw explicit error) instead of falling back to `Math.random()`.

### Fixed
- Replaced manual 1-byte string assembly in `decodeBase64Url` with UTF-8 `TextDecoder` decoding (`decodeBase64UrlUtf8`) so multi-byte UTF-8 characters in JWT claims decode cleanly.
- Prevented saving `"undefined"` as `refresh_token` and skipped background auto-refresh when a token response omits `refresh_token` (e.g., short-lived non-refreshable impersonation tokens).

## [1.0.0] - 2026-10-26

### Added
- Initial release of `@witsauth/react-native-client` for Expo and Bare React Native CLI on Android and iOS.
- RFC 8252 system browser OAuth 2.0 + PKCE (`S256`) flow with pure-TS SHA-256 support for React Native Hermes.
- Built-in hardware-backed storage adapters for `expo-secure-store` and `react-native-keychain`.
- Automatic token refresh and foreground `AppState` token synchronization.
- Axios bearer token injection and 401 refresh-and-retry queue interceptor.
- Hosted Account Management handoff (`navigateToAccountManagement()`).
