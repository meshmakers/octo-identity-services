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
  groups: string[];
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

// === Self-Service Verified Identifiers (AB#5135 / AB#5123) ===

export type VerifiedIdentifierKind =
  | 'PhoneNumber'
  | 'EmailAddress'
  | 'EntraIdObjectId'
  | 'ClientCertificateFingerprint';

export type EnrollmentTrust = 'None' | 'Weak' | 'Strong';

export type IdentifierSource = 'SelfService' | 'Admin' | 'IdentityProvider';

/** One of the signed-in user's own verified channel identifiers. */
export interface VerifiedIdentifier {
  rtId: string;
  identifierKind: VerifiedIdentifierKind;
  identifierValue: string;
  enrollmentTrust: EnrollmentTrust;
  source: IdentifierSource;
  enrolledAt?: string | null;
  lastVerifiedAt?: string | null;
  validUntil?: string | null;
  isValid: boolean;
}

export interface StartPhoneEnrollmentRequest {
  phoneNumber: string;
}

export interface StartPhoneEnrollmentResult {
  status: string;
  success: boolean;
  normalizedNumber?: string | null;
  maskedDestination?: string | null;
  expiresAtUtc?: string | null;
}

export interface VerifyPhoneRequest {
  phoneNumber: string;
  code: string;
}

export interface StartEmailEnrollmentRequest {
  email: string;
}

export interface StartEmailEnrollmentResult {
  status: string;
  success: boolean;
  normalizedEmail?: string | null;
  maskedDestination?: string | null;
  expiresAtUtc?: string | null;
}

export interface VerifyEmailRequest {
  email: string;
  code: string;
}

/** Shared OTP-verification response shape (phone + email). */
export interface VerifyOtpResult {
  status: string;
  success: boolean;
  attemptsRemaining: number;
}

export interface EnrollCertificateRequest {
  certificateBase64: string;
}

export interface EnrollCertificateResult {
  status: string;
  success: boolean;
  fingerprint?: string | null;
  validUntilUtc?: string | null;
}

export interface RemoveIdentifierRequest {
  identifierKind: VerifiedIdentifierKind;
  identifierValue: string;
}

export interface RemoveIdentifierResult {
  success: boolean;
}
