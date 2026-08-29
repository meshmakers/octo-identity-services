import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
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
  changeDetection: ChangeDetectionStrategy.Eager,
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
  private handoffAlreadyBounced = false; // Guards the parent bounce against ping-ponging

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
    // Set when we already sent the user to the parent once. Without it a hand-off that keeps
    // failing would ping-pong between parent and child forever.
    this.handoffAlreadyBounced = this.route.snapshot.queryParams['xtBounced'] === '1';
    if (crossTenantAutoLogin || this.handoffAlreadyBounced) {
      this.stripQueryParams(['crossTenantAutoLogin', 'xtBounced']);
    }

    this.loadContext(crossTenantAutoLogin);
  }

  private loadContext(autoLoginParentTenantId?: string): void {
    this.loading = true;
    this.authApi.getLoginContext(this.returnUrl).subscribe({
      next: (context) => {
        if (context.setupRequired) {
          this.router.navigate(['/', this.tenantId, 'setup']);
          return;
        }
        this.context = context;

        // Coming back from the parent: finish what we started. The bounce guard set above stops
        // this from starting another round trip if it fails again.
        if (autoLoginParentTenantId) {
          this.loading = false;
          this.performCrossTenantAutoLogin(autoLoginParentTenantId);
          return;
        }

        // AB#4961: a pending request plus an existing session leaves nothing to ask. Continuing
        // beats rendering "you are signed in as ..." with no way back to where the user was going.
        if (context.isAuthenticated && this.returnUrl) {
          this.continueToReturnUrl();
          return;
        }

        // AB#4964: this tenant borrows its identity from exactly one parent, so the form below can
        // only ever forward the credentials there anyway. Try the hand-off silently first — if the
        // parent session is still alive the user never sees a second mask.
        const parentTenantId = this.soleParentTenantId(context);
        if (parentTenantId && !context.isAuthenticated && this.returnUrl) {
          this.tryQuietCrossTenantHandoff(parentTenantId);
          return;
        }

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
          isAuthenticated: false,
          setupRequired: false,
          tenantUnavailable: false
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

  private stripQueryParams(paramsToRemove: string[]): void {
    const params = { ...this.route.snapshot.queryParams };
    for (const param of paramsToRemove) {
      delete params[param];
    }
    this.router.navigate([], { relativeTo: this.route, queryParams: params, replaceUrl: true });
  }

  /**
   * The parent tenant to hand off to, but only when it is the ONLY way into this tenant. With a
   * second external provider the choice belongs to the user, and with none there is nothing to
   * hand off to.
   */
  private soleParentTenantId(context: LoginContext): string | undefined {
    if (context.externalProviders.length !== 1) {
      return undefined;
    }

    const provider = context.externalProviders[0];
    if (!provider.isParentTenant) {
      return undefined;
    }

    const parentTenantId = provider.scheme.replace('octo-tenant-', '');
    return parentTenantId.toLowerCase() === this.tenantId.toLowerCase()
      ? undefined
      : parentTenantId;
  }

  /**
   * Completes the hand-off without asking, if the parent session is still alive.
   *
   * Deliberately does NOT fall back to the parent's login page: sending the user there unasked
   * would strand anyone holding a local account in this tenant. A failure here just reveals the
   * normal form, with the provider button still on it.
   */
  private tryQuietCrossTenantHandoff(parentTenantId: string): void {
    this.authApi.getCrossTenantToken(parentTenantId, this.tenantId).subscribe({
      next: (tokenResult) => this.redeemCrossTenantToken(tokenResult.token, () => {
        this.loading = false;
      }),
      error: () => {
        this.loading = false;
      }
    });
  }

  private performCrossTenantAutoLogin(parentTenantId: string): void {
    // Guard: if the parent tenant is the same as the current tenant, there's nothing to auto-login.
    // This happens when the redirect chain lands back on the parent's own login page after cookie expiry.
    if (parentTenantId.toLowerCase() === this.tenantId.toLowerCase()) {
      return;
    }
    this.submitting = true;
    this.errorMessage = undefined;
    this.performCrossTenantLogin(parentTenantId);
  }

  private performCrossTenantLogin(parentTenantId: string): void {
    // Step 1: Try to get a cross-tenant token from the parent tenant.
    // The browser sends the parent's scoped cookie automatically.
    this.authApi.getCrossTenantToken(parentTenantId, this.tenantId).subscribe({
      next: (tokenResult) => {
        this.redeemCrossTenantToken(tokenResult.token, (message) => {
          this.submitting = false;
          this.errorMessage = message;
        });
      },
      error: () => {
        this.submitting = false;

        // No usable session in the parent tenant → authenticate there once, then come back and
        // complete the exchange. Only ever once: if we have already been bounced, fall back to
        // this tenant's own form rather than starting the round trip over.
        if (this.handoffAlreadyBounced) {
          this.errorMessage = 'Cross-tenant login failed';
          return;
        }

        const childReturnUrl = `/${this.tenantId}/login`
          + `?returnUrl=${encodeURIComponent(this.returnUrl)}`
          + `&crossTenantAutoLogin=${encodeURIComponent(parentTenantId)}`
          + '&xtBounced=1';
        window.location.href = `/${parentTenantId}/login`
          + `?returnUrl=${encodeURIComponent(childReturnUrl)}`;
      }
    });
  }

  /** Step 2 of the hand-off: redeem the parent's token for a session in this tenant. */
  private redeemCrossTenantToken(token: string, onFailure: (message?: string) => void): void {
    this.authApi.crossTenantLogin({ token, returnUrl: this.returnUrl }).subscribe({
      next: (loginResult) => {
        if (loginResult.success && loginResult.redirectUrl) {
          window.location.href = loginResult.redirectUrl;
        } else if (loginResult.success) {
          this.submitting = false;
          this.router.navigate(['/', this.tenantId, 'manage']);
        } else {
          onFailure(loginResult.errorMessage || 'Cross-tenant login failed');
        }
      },
      error: () => onFailure('Cross-tenant login failed')
    });
  }

  private continueToReturnUrl(): void {
    // returnUrl is a server-side path — the IdentityServer authorize callback, or a child tenant's
    // login page resuming a hand-off — so it needs a full navigation, not an Angular route.
    if (!this.isSafeReturnUrl(this.returnUrl)) {
      this.loading = false;
      return;
    }
    window.location.href = this.returnUrl;
  }

  /**
   * returnUrl arrives from the query string, so it may only ever be a site-relative path. Anything
   * absolute or protocol-relative ("//evil.example", and "/\evil.example" which browsers treat the
   * same way) would make this an open redirect.
   */
  private isSafeReturnUrl(url: string): boolean {
    return /^\/(?![/\\])/.test(url);
  }

  get hasExternalProviders(): boolean {
    return (this.context?.externalProviders?.length ?? 0) > 0;
  }

  get showLocalLogin(): boolean {
    return this.context?.enableLocalLogin ?? true;
  }

  continueAsUser(): void {
    // AB#4961: when a request is pending, "continue" means finish it — not detour to the profile
    // page, which used to drop the user out of whatever flow brought them here.
    if (this.isSafeReturnUrl(this.returnUrl)) {
      this.continueToReturnUrl();
      return;
    }

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
