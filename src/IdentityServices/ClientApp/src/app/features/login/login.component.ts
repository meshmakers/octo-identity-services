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
    this.returnUrl = this.route.snapshot.queryParams['ReturnUrl'] || '';

    this.loadContext();
  }

  private loadContext(): void {
    this.loading = true;
    this.authApi.getLoginContext(this.returnUrl).subscribe({
      next: (context) => {
        this.context = context;
        this.loading = false;
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
    } else {
      // OAuth providers redirect to external provider
      this.authApi.initiateExternalLogin(provider.scheme, this.returnUrl);
    }
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
