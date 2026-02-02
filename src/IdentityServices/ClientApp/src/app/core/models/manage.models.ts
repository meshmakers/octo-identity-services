export interface UserProfile {
  id: string;
  userName: string;
  email?: string;
  emailConfirmed: boolean;
  phoneNumber?: string;
  phoneNumberConfirmed: boolean;
  twoFactorEnabled: boolean;
  hasPassword: boolean;
  externalLogins: ExternalLoginInfo[];
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
