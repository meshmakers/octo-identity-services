import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { getTenantIdFromUrl } from '../utils/tenant.utils';
import {
  LoginContext,
  LoginRequest,
  LoginResult,
  LogoutContext,
  LogoutRequest,
  LogoutResult,
  ExternalProvider,
  ForgotPasswordRequest,
  ForgotPasswordResult,
  ResetPasswordRequest,
  ResetPasswordResult,
  ValidateResetTokenResult,
  TwoFactorLoginRequest,
  TwoFactorEmailLoginRequest,
  TwoFactorLoginResult,
  RecoveryCodeLoginRequest,
  SendTwoFactorEmailResult,
  LdapLoginRequest,
  LdapLoginResult
} from '../models/login.models';

@Injectable({ providedIn: 'root' })
export class AuthApiService {
  private http = inject(HttpClient);

  getLoginContext(returnUrl: string): Observable<LoginContext> {
    return this.http.get<LoginContext>('/api/auth/login-context', {
      params: { returnUrl }
    });
  }

  login(request: LoginRequest): Observable<LoginResult> {
    return this.http.post<LoginResult>('/api/auth/login', request);
  }

  getExternalProviders(): Observable<ExternalProvider[]> {
    return this.http.get<ExternalProvider[]>('/api/auth/external-providers');
  }

  initiateExternalLogin(scheme: string, returnUrl: string): void {
    // window.location.href bypasses Angular's HTTP interceptor, so we must include tenant ID manually
    const tenantId = getTenantIdFromUrl();

    const url = `/${tenantId}/api/auth/external-login?scheme=${encodeURIComponent(scheme)}&returnUrl=${encodeURIComponent(returnUrl)}`;
    window.location.href = url;
  }

  getLogoutContext(logoutId: string): Observable<LogoutContext> {
    return this.http.get<LogoutContext>('/api/auth/logout-context', {
      params: { logoutId }
    });
  }

  logout(request: LogoutRequest): Observable<LogoutResult> {
    return this.http.post<LogoutResult>('/api/auth/logout', request);
  }

  forgotPassword(request: ForgotPasswordRequest): Observable<ForgotPasswordResult> {
    return this.http.post<ForgotPasswordResult>('/api/auth/forgot-password', request);
  }

  resetPassword(request: ResetPasswordRequest): Observable<ResetPasswordResult> {
    return this.http.post<ResetPasswordResult>('/api/auth/reset-password', request);
  }

  validateResetToken(email: string, token: string): Observable<ValidateResetTokenResult> {
    return this.http.get<ValidateResetTokenResult>('/api/auth/validate-reset-token', {
      params: { email, token }
    });
  }

  // === Two-Factor Authentication ===

  loginTwoFactor(request: TwoFactorLoginRequest): Observable<TwoFactorLoginResult> {
    return this.http.post<TwoFactorLoginResult>('/api/auth/login-2fa', request);
  }

  loginTwoFactorEmail(request: TwoFactorEmailLoginRequest): Observable<TwoFactorLoginResult> {
    return this.http.post<TwoFactorLoginResult>('/api/auth/login-2fa-email', request);
  }

  sendTwoFactorEmail(): Observable<SendTwoFactorEmailResult> {
    return this.http.post<SendTwoFactorEmailResult>('/api/auth/send-2fa-email', {});
  }

  loginRecovery(request: RecoveryCodeLoginRequest): Observable<TwoFactorLoginResult> {
    return this.http.post<TwoFactorLoginResult>('/api/auth/login-recovery', request);
  }

  // === LDAP Authentication ===

  ldapLogin(request: LdapLoginRequest): Observable<LdapLoginResult> {
    return this.http.post<LdapLoginResult>('/api/auth/ldap-login', request);
  }
}
