import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  UserProfile,
  ChangePasswordRequest,
  SetPasswordRequest,
  PasswordResult,
  RemoveExternalLoginRequest,
  ExternalLoginInfo,
  TwoFactorStatus,
  AuthenticatorSetup,
  VerifyAuthenticatorRequest,
  VerifyAuthenticatorResult,
  DisableTwoFactorRequest,
  DisableTwoFactorResult,
  GenerateRecoveryCodesResult
} from '../models/manage.models';
import { ExternalProvider } from '../models/login.models';

@Injectable({ providedIn: 'root' })
export class ManageApiService {
  private http = inject(HttpClient);

  // === Profile ===

  getProfile(): Observable<UserProfile> {
    return this.http.get<UserProfile>('/api/manage/profile');
  }

  // === Password ===

  changePassword(request: ChangePasswordRequest): Observable<PasswordResult> {
    return this.http.post<PasswordResult>('/api/manage/change-password', request);
  }

  setPassword(request: SetPasswordRequest): Observable<PasswordResult> {
    return this.http.post<PasswordResult>('/api/manage/set-password', request);
  }

  // === External Logins ===

  getExternalLogins(): Observable<ExternalLoginInfo[]> {
    return this.http.get<ExternalLoginInfo[]>('/api/manage/external-logins');
  }

  getAvailableProviders(): Observable<ExternalProvider[]> {
    return this.http.get<ExternalProvider[]>('/api/manage/available-providers');
  }

  addExternalLogin(provider: string): void {
    // Redirect to add external login endpoint
    const returnUrl = window.location.href;
    window.location.href = `/api/manage/link-login?provider=${encodeURIComponent(provider)}&returnUrl=${encodeURIComponent(returnUrl)}`;
  }

  removeExternalLogin(request: RemoveExternalLoginRequest): Observable<PasswordResult> {
    return this.http.post<PasswordResult>('/api/manage/remove-external-login', request);
  }

  // === Two-Factor Authentication ===

  getTwoFactorStatus(): Observable<TwoFactorStatus> {
    return this.http.get<TwoFactorStatus>('/api/manage/2fa/status');
  }

  setupAuthenticator(): Observable<AuthenticatorSetup> {
    return this.http.post<AuthenticatorSetup>('/api/manage/2fa/authenticator/setup', {});
  }

  verifyAuthenticator(request: VerifyAuthenticatorRequest): Observable<VerifyAuthenticatorResult> {
    return this.http.post<VerifyAuthenticatorResult>('/api/manage/2fa/authenticator/verify', request);
  }

  disableTwoFactor(request: DisableTwoFactorRequest): Observable<DisableTwoFactorResult> {
    return this.http.post<DisableTwoFactorResult>('/api/manage/2fa/disable', request);
  }

  generateRecoveryCodes(): Observable<GenerateRecoveryCodesResult> {
    return this.http.post<GenerateRecoveryCodesResult>('/api/manage/2fa/recovery-codes/generate', {});
  }
}
