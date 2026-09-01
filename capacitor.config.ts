import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.edy.scanurl.family',
  appName: 'EDY ScanURL Family',
  webDir: 'apps/web/dist',
  loggingBehavior: 'none',
  android: {
    allowMixedContent: false,
    webContentsDebuggingEnabled: false,
    useLegacyBridge: false,
    resolveServiceWorkerRequests: false,
  },
  server: {
    hostname: 'localhost',
    androidScheme: 'https',
    cleartext: false,
    allowNavigation: [],
  },
};

export default config;
