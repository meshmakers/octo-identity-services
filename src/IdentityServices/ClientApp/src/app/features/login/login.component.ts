import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ExternalProviderButtonComponent } from '../../shared/components/external-provider-button/external-provider-button.component';
import { AuthApiService } from '../../core/services/auth-api.service';
import { LoginContext, LoginRequest, ExternalProvider } from '../../core/models/login.models';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    RouterLink,
    LcarsPanelComponent,
    LcarsHeaderComponent,
    ExternalProviderButtonComponent
  ],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private authApi = inject(AuthApiService);

  // State
  loading = true;
  submitting = false;
  errorMessage?: string;
  context?: LoginContext;
  showLoginForm = false; // Used to override isAuthenticated and show login form

  // Form data
  username = '';
  password = '';
  rememberLogin = false;

  // Computed
  returnUrl = '';
  tenantId = 'System';

  ngOnInit(): void {
    this.tenantId = this.route.snapshot.params['tenantId'] || 'System';
    // Support both 'ReturnUrl' (from IdentityServer) and 'returnUrl' (from Angular navigation)
    this.returnUrl = this.route.snapshot.queryParams['ReturnUrl']
                  || this.route.snapshot.queryParams['returnUrl']
                  || '';

    const crossTenantAutoLogin = this.route.snapshot.queryParams['crossTenantAutoLogin'];
    if (crossTenantAutoLogin) {
      this.stripQueryParam('crossTenantAutoLogin');
    }

    this.loadContext(crossTenantAutoLogin);
  }

  private loadContext(autoLoginParentTenantId?: string): void {
    this.loading = true;
    this.authApi.getLoginContext(this.returnUrl).subscribe({
      next: (context) => {
        this.context = context;
        this.loading = false;
        if (autoLoginParentTenantId) {
          this.performCrossTenantAutoLogin(autoLoginParentTenantId);
        }
      },
      error: (error) => {
        console.error('Failed to load login context', error);
        this.loading = false;
        // Use default context on error
        this.context = {
          returnUrl: this.returnUrl,
          externalProviders: [],
          allowRememberLogin: true,
          enableLocalLogin: true,
          isAuthenticated: false
        };
      }
    });
  }

  onSubmit(): void {
    if (!this.username || !this.password) {
      this.errorMessage = 'Please enter username and password';
      return;
    }

    this.submitting = true;
    this.errorMessage = undefined;

    const request: LoginRequest = {
      username: this.username,
      password: this.password,
      rememberLogin: this.rememberLogin,
      returnUrl: this.returnUrl
    };

    this.authApi.login(request).subscribe({
      next: (result) => {
        this.submitting = false;
        if (result.success && result.redirectUrl) {
          window.location.href = result.redirectUrl;
        } else if (result.requiresTwoFactor) {
          // Redirect to 2FA page with capability information
          this.router.navigate(['..', '2fa-login'], {
            relativeTo: this.route,
            queryParams: {
              returnUrl: this.returnUrl,
              totp: result.canUseTotpAuthenticator ? 'true' : 'false',
              email: result.canUseEmailCode ? 'true' : 'false'
            }
          });
        } else {
          this.errorMessage = result.errorMessage || 'Login failed';
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.message || 'An error occurred during login';
      }
    });
  }

  onExternalLogin(provider: ExternalProvider): void {
    if (provider.isLdap) {
      // LDAP providers use a form-based login page
      this.router.navigate(['/', this.tenantId, 'ldap-login'], {
        queryParams: {
          scheme: provider.scheme,
          name: provider.displayName,
          returnUrl: this.returnUrl
        }
      });
    } else if (provider.isParentTenant) {
      // Extract parent tenant ID from scheme (e.g. "octo-tenant-OctoSystem" → "OctoSystem")
      const parentTenantId = provider.scheme.replace('octo-tenant-', '');
      this.submitting = true;
      this.errorMessage = undefined;

      this.performCrossTenantLogin(parentTenantId);
    } else {
      // OAuth providers redirect to external provider
      this.authApi.initiateExternalLogin(provider.scheme, this.returnUrl);
    }
  }

  private stripQueryParam(param: string): void {
    const params = { ...this.route.snapshot.queryParams };
    delete params[param];
    this.router.navigate([], { relativeTo: this.route, queryParams: params, replaceUrl: true });
  }

  private performCrossTenantAutoLogin(parentTenantId: string): void {
    this.submitting = true;
    this.errorMessage = undefined;
    this.performCrossTenantLogin(parentTenantId);
  }

  private performCrossTenantLogin(parentTenantId: string): void {
    // Step 1: Try to get a cross-tenant token from the parent tenant.
    // The browser sends the parent's scoped cookie automatically.
    this.authApi.getCrossTenantToken(parentTenantId, this.tenantId).subscribe({
      next: (tokenResult) => {
        // Step 2: Exchange the token for a session in the current (child) tenant
        this.authApi.crossTenantLogin({ token: tokenResult.token, returnUrl: this.returnUrl }).subscribe({
          next: (loginResult) => {
            this.submitting = false;
            if (loginResult.success && loginResult.redirectUrl) {
              window.location.href = loginResult.redirectUrl;
            } else if (loginResult.success) {
              this.router.navigate(['/', this.tenantId, 'manage']);
            } else {
              this.errorMessage = loginResult.errorMessage || 'Cross-tenant login failed';
            }
          },
          error: () => {
            this.submitting = false;
            this.errorMessage = 'Cross-tenant login failed';
          }
        });
      },
      error: () => {
        // No active session in parent tenant → redirect to parent's login page.
        // After authenticating there, the user is redirected back with crossTenantAutoLogin
        // to auto-complete the token exchange.
        this.submitting = false;
        const childReturnUrl = `/${this.tenantId}/login`
          + `?returnUrl=${encodeURIComponent(this.returnUrl)}`
          + `&crossTenantAutoLogin=${encodeURIComponent(parentTenantId)}`;
        window.location.href = `/${parentTenantId}/login`
          + `?returnUrl=${encodeURIComponent(childReturnUrl)}`;
      }
    });
  }

  get hasExternalProviders(): boolean {
    return (this.context?.externalProviders?.length ?? 0) > 0;
  }

  get showLocalLogin(): boolean {
    return this.context?.enableLocalLogin ?? true;
  }

  continueAsUser(): void {
    // Navigate to profile/manage page
    this.router.navigate(['/', this.tenantId, 'manage']);
  }

  signOutAndSignIn(): void {
    // Just show the login form - don't log out yet
    // The new login will replace the current session
    this.showLoginForm = true;
  }

  cancelSwitchUser(): void {
    // Go back to the "already authenticated" view
    this.showLoginForm = false;
    this.username = '';
    this.password = '';
    this.errorMessage = undefined;
  }
}
