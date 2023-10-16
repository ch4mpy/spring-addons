import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.c4_soft.spring_addons.bff',
  appName: 'frontend',
  webDir: 'dist/frontend',
  server: {
    androidScheme: 'https'
  }
};

export default config;
