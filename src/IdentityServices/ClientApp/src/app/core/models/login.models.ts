export interface ExternalProvider {
  scheme: string;
  displayName: string;
  isLdap: boolean;
}

export interface LoginContext {
  returnUrl: string;
  clientName?: string;
  clientLogoUrl?: string;
  externalProviders: ExternalProvider[];
  allowRememberLogin: boolean;
  enableLocalLogin: boolean;
  isAuthenticated: boolean;
  username?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
  rememberLogin: boolean;
  returnUrl: string;
}

export interface LoginResult {
  success: boolean;
  redirectUrl?: string;
  errorMessage?: string;
  isLockedOut?: boolean;
  requiresTwoFactor?: boolean;
  canUseTotpAuthenticator?: boolean;
  canUseEmailCode?: boolean;
}

export interface LogoutContext {
  logoutId: string;
  showLogoutPrompt: boolean;
  postLogoutRedirectUri?: string;
  clientName?: string;
}

export interface LogoutRequest {
  logoutId: string;
}

export interface LogoutResult {
  success: boolean;
  postLogoutRedirectUri?: string;
  clientName?: string;
  signOutIframeUrl?: string;
  automaticRedirectAfterSignOut: boolean;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ForgotPasswordResult {
  success: boolean;
  errorMessage?: string;
}

export interface ResetPasswordRequest {
  email: string;
  token: string;
  newPassword: string;
  confirmPassword: string;
}

export interface ResetPasswordResult {
  success: boolean;
  errorMessage?: string;
  errors?: string[];
}

export interface ValidateResetTokenResult {
  isValid: boolean;
}

// Two-Factor Authentication Types

export interface TwoFactorLoginRequest {
  code: string;
  rememberMachine: boolean;
  returnUrl?: string;
}

export interface TwoFactorEmailLoginRequest {
  code: string;
  rememberMachine: boolean;
  returnUrl?: string;
}

export interface TwoFactorLoginResult {
  success: boolean;
  redirectUrl?: string;
  errorMessage?: string;
}

export interface RecoveryCodeLoginRequest {
  recoveryCode: string;
  returnUrl?: string;
}

export interface SendTwoFactorEmailResult {
  success: boolean;
  errorMessage?: string;
}

// LDAP Authentication Types

export interface LdapLoginRequest {
  scheme: string;
  username: string;
  password: string;
  returnUrl?: string;
}

export interface LdapLoginResult {
  success: boolean;
  redirectUrl?: string;
  errorMessage?: string;
}
