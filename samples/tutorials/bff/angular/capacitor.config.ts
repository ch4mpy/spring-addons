import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.c4_soft.demo.bff',
  appName: 'bff-ui',
  webDir: 'dist/bff-ui',
  server: {
    androidScheme: 'https'
  },
  android: {
    path: 'projects/bff-ui/android'
  }
};

export default config;
