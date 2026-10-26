# @witsauth/react-native-client

Official React Native SDK for **WitsAuth** OAuth 2.0 + PKCE authentication, token lifecycle management, Axios interceptor integration, and hosted Account Management on **Android** and **iOS** (supporting both **Expo** and **Bare React Native CLI**).

---

## Features

- **RFC 8252 System Browser OAuth 2.0 + PKCE (`S256`)**: Uses `ASWebAuthenticationSession` on iOS and Chrome Custom Tabs on Android.
- **Hermes-Ready Pure-TS SHA-256 PKCE**: Works out-of-the-box on React Native Hermes without requiring native Web Crypto polyfills.
- **Hardware-Backed Secure Token Storage**: Built-in adapters for `expo-secure-store` (Expo) and `react-native-keychain` (Bare React Native CLI), backed by iOS Keychain and Android Keystore.
- **Automatic Token Refresh**: Proactively refreshes expiring tokens and refreshes automatically when the app returns to the foreground (`AppState`).
- **Hosted Account Management (`/auth/account`)**: Allows users to change their password, update their profile, and verify their mobile phone number via OTP using a single-use handoff ticket (`navigateToAccountManagement()`).
- **Axios Interceptor**: Automatically attaches `Authorization: Bearer <token>` and queues/retries concurrent `401 Unauthorized` requests.

---

## 1. WitsAuth Console Configuration

1. Open the **WitsAuth Console** and create or edit a **Regular Web / Mobile Application**.
2. Set **Framework** to **React Native (Mobile)**.
3. Add your mobile deep-link callback URI under **Allowed Callback URLs**, for example:
   ```text
   myapp://auth/callback
   ```

---

## 2. Installation & Setup

### Option A: Expo (Managed or Prebuild Workflow)

```bash
npx expo install @witsauth/react-native-client expo-web-browser expo-secure-store
```

Configure your custom scheme in `app.json`:

```json
{
  "expo": {
    "name": "My App",
    "slug": "my-app",
    "scheme": "myapp"
  }
}
```

Initialize `AuthProvider` in your app root:

```tsx
import React from 'react';
import { AppState } from 'react-native';
import * as WebBrowser from 'expo-web-browser';
import * as SecureStore from 'expo-secure-store';
import {
  AuthProvider,
  createExpoSecureStoreAdapter,
  createExpoWebBrowserLauncher,
  OAuth2NativeConfig
} from '@witsauth/react-native-client';

WebBrowser.maybeCompleteAuthSession();

const authConfig: OAuth2NativeConfig = {
  clientId: 'YOUR_CLIENT_ID',
  authorizationEndpoint: 'https://your-tenant.witsauth.com/auth/authorize',
  tokenEndpoint: 'https://your-tenant.witsauth.com/oauth/token',
  revokeEndpoint: 'https://your-tenant.witsauth.com/oauth/revoke',
  redirectUri: 'myapp://auth/callback',
  scope: 'openid profile email offline_access',
  storage: createExpoSecureStoreAdapter(SecureStore),
  openAuthSession: createExpoWebBrowserLauncher(WebBrowser)
};

export default function App() {
  return (
    <AuthProvider
      config={authConfig}
      subscribeAppState={(listener) => {
        const sub = AppState.addEventListener('change', listener);
        return () => sub.remove();
      }}
    >
      {/* Your App Navigation */}
    </AuthProvider>
  );
}
```

---

### Option B: Bare React Native CLI (Android & iOS)

```bash
npm install @witsauth/react-native-client react-native-inappbrowser-reborn react-native-keychain
cd ios && pod install
```

#### Android Deep-Link Configuration (`android/app/src/main/AndroidManifest.xml`)

Add an `<intent-filter>` inside your main `<activity>`:

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="myapp" android:host="auth" android:pathPrefix="/callback" />
</intent-filter>
```

#### iOS Deep-Link Configuration (`ios/<YourApp>/Info.plist`)

Register `CFBundleURLTypes`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleTypeRole</key>
    <string>Editor</string>
    <key>CFBundleURLName</key>
    <string>com.yourcompany.myapp</string>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>myapp</string>
    </array>
  </dict>
</array>
```

Initialize `AuthProvider` with `react-native-keychain` and `react-native-inappbrowser-reborn`:

```tsx
import React from 'react';
import { AppState } from 'react-native';
import InAppBrowser from 'react-native-inappbrowser-reborn';
import * as Keychain from 'react-native-keychain';
import {
  AuthProvider,
  createKeychainStorageAdapter,
  createInAppBrowserLauncher,
  OAuth2NativeConfig
} from '@witsauth/react-native-client';

const authConfig: OAuth2NativeConfig = {
  clientId: 'YOUR_CLIENT_ID',
  authorizationEndpoint: 'https://your-tenant.witsauth.com/auth/authorize',
  tokenEndpoint: 'https://your-tenant.witsauth.com/oauth/token',
  revokeEndpoint: 'https://your-tenant.witsauth.com/oauth/revoke',
  redirectUri: 'myapp://auth/callback',
  scope: 'openid profile email offline_access',
  storage: createKeychainStorageAdapter(Keychain),
  openAuthSession: createInAppBrowserLauncher(InAppBrowser)
};
```

---

## 3. Using `useAuth()` for Login, Logout & Account Management

```tsx
import React from 'react';
import { View, Button, Text } from 'react-native';
import { useAuth } from '@witsauth/react-native-client';

export function ProfileScreen() {
  const {
    isAuthenticated,
    isLoading,
    login,
    logout,
    navigateToAccountManagement
  } = useAuth();

  if (isLoading) {
    return <Text>Loading...</Text>;
  }

  if (!isAuthenticated) {
    return <Button title="Sign In with WitsAuth" onPress={login} />;
  }

  return (
    <View>
      <Button
        title="Manage Account (Password & Phone)"
        onPress={navigateToAccountManagement}
      />
      <Button title="Sign Out" onPress={logout} />
    </View>
  );
}
```
