import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(import.meta.dirname, 'src/index.ts'),
      name: 'WitsAuthReactNativeClient',
      fileName: (format) => `index.${format}.js`
    },
    rollupOptions: {
      external: [
        'react',
        'react/jsx-runtime',
        'react/jsx-dev-runtime',
        'react-native',
        'axios',
        'expo-web-browser',
        'expo-secure-store',
        'react-native-inappbrowser-reborn',
        'react-native-keychain'
      ],
      output: {
        globals: {
          react: 'React',
          'react-native': 'ReactNative',
          'react/jsx-runtime': 'jsxRuntime',
          'react/jsx-dev-runtime': 'jsxDevRuntime',
          axios: 'axios'
        }
      }
    }
  }
});
