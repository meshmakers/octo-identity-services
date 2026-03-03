export interface UserProfile {
  id: string;
  tenantId: string;
  userName: string;
  email?: string;
  emailConfirmed: boolean;
  phoneNumber?: string;
  phoneNumberConfirmed: boolean;
  twoFactorEnabled: boolean;
  hasPassword: boolean;
  externalLogins: ExternalLoginInfo[];
  roles: string[];
  allowedTenants: string[];
}

export interface ExternalLoginInfo {
  loginProvider: string;
  providerDisplayName: string;
  providerKey: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export interface SetPasswordRequest {
  newPassword: string;
  confirmPassword: string;
}

export interface PasswordResult {
  success: boolean;
  errorMessage?: string;
  errors?: string[];
}

export interface AddExternalLoginResult {
  success: boolean;
  errorMessage?: string;
}

export interface RemoveExternalLoginRequest {
  loginProvider: string;
  providerKey: string;
}

// Two-Factor Authentication Types

export interface TwoFactorStatus {
  enabled: boolean;
  hasAuthenticator: boolean;
  recoveryCodesLeft: number;
}

export interface AuthenticatorSetup {
  sharedKey: string;
  qrCodeUri: string;
  qrCodeImage: string;
}

export interface VerifyAuthenticatorRequest {
  code: string;
}

export interface VerifyAuthenticatorResult {
  success: boolean;
  errorMessage?: string;
  recoveryCodes: string[];
}

export interface DisableTwoFactorRequest {
  code: string;
}

export interface DisableTwoFactorResult {
  success: boolean;
  errorMessage?: string;
}

export interface GenerateRecoveryCodesResult {
  recoveryCodes: string[];
}
