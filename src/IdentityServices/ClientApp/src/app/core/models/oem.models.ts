export interface OemConfig {
  appName: string;
  logoUrl?: string;
  faviconUrl?: string;
  primaryColor?: string;
  accentColor?: string;
  hideNavigation: boolean;
}

export const defaultOemConfig: OemConfig = {
  appName: 'OctoMesh Identity',
  logoUrl: '/assets/images/logo.svg',
  hideNavigation: false
};
