import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { AuthApiService } from '../../core/services/auth-api.service';

type TwoFactorMethod = 'totp' | 'email' | 'recovery';

@Component({
  selector: 'app-two-factor-login',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header subtitle="Two-Factor Authentication"></app-lcars-header>

        <!-- Method Tabs -->
        <div class="method-tabs">
          <button
            *ngIf="canUseTotp"
            type="button"
            class="method-tab"
            [class.method-tab--active]="activeMethod === 'totp'"
            (click)="setMethod('totp')">
            Authenticator
          </button>
          <button
            *ngIf="canUseEmail"
            type="button"
            class="method-tab"
            [class.method-tab--active]="activeMethod === 'email'"
            (click)="setMethod('email')">
            Email
          </button>
          <button
            type="button"
            class="method-tab"
            [class.method-tab--active]="activeMethod === 'recovery'"
            (click)="setMethod('recovery')">
            Recovery
          </button>
        </div>

        <div *ngIf="errorMessage" class="lcars-error-message">
          {{ errorMessage }}
        </div>

        <!-- TOTP Method -->
        <form *ngIf="activeMethod === 'totp'" (ngSubmit)="onSubmitTotp()">
          <p class="method-description">
            Enter the 6-digit code from your authenticator app.
          </p>

          <div class="lcars-form-group">
            <label for="totpCode">Verification Code</label>
            <input
              type="text"
              id="totpCode"
              name="totpCode"
              [(ngModel)]="totpCode"
              placeholder="000000"
              maxlength="6"
              autocomplete="one-time-code"
              [disabled]="submitting" />
          </div>

          <div class="lcars-form-group lcars-checkbox-group">
            <label class="lcars-checkbox">
              <input
                type="checkbox"
                [(ngModel)]="rememberMachine"
                name="rememberMachine"
                [disabled]="submitting" />
              <span class="lcars-checkbox__label">Remember this machine</span>
            </label>
          </div>

          <div class="lcars-actions">
            <button
              type="submit"
              class="lcars-button-primary"
              [disabled]="submitting || totpCode.length < 6">
              {{ submitting ? 'Verifying...' : 'Verify' }}
            </button>
          </div>
        </form>

        <!-- Email Method -->
        <form *ngIf="activeMethod === 'email'" (ngSubmit)="onSubmitEmail()">
          <p class="method-description">
            We'll send a verification code to your email address.
          </p>

          <div *ngIf="!emailSent" class="lcars-actions">
            <button
              type="button"
              class="lcars-button-primary"
              [disabled]="sendingEmail"
              (click)="sendEmailCode()">
              {{ sendingEmail ? 'Sending...' : 'Send Code' }}
            </button>
          </div>

          <ng-container *ngIf="emailSent">
            <div class="success-message">
              Code sent! Check your email.
            </div>

            <div class="lcars-form-group">
              <label for="emailCode">Email Code</label>
              <input
                type="text"
                id="emailCode"
                name="emailCode"
                [(ngModel)]="emailCode"
                placeholder="000000"
                maxlength="6"
                autocomplete="one-time-code"
                [disabled]="submitting" />
            </div>

            <div class="lcars-form-group lcars-checkbox-group">
              <label class="lcars-checkbox">
                <input
                  type="checkbox"
                  [(ngModel)]="rememberMachine"
                  name="rememberMachineEmail"
                  [disabled]="submitting" />
                <span class="lcars-checkbox__label">Remember this machine</span>
              </label>
            </div>

            <div class="lcars-actions">
              <button
                type="submit"
                class="lcars-button-primary"
                [disabled]="submitting || emailCode.length < 6">
                {{ submitting ? 'Verifying...' : 'Verify' }}
              </button>
              <button
                type="button"
                class="lcars-button-outline"
                [disabled]="sendingEmail"
                (click)="sendEmailCode()">
                Resend Code
              </button>
            </div>
          </ng-container>
        </form>

        <!-- Recovery Method -->
        <form *ngIf="activeMethod === 'recovery'" (ngSubmit)="onSubmitRecovery()">
          <div class="warning-message">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
            <p>Recovery codes are single-use. Once used, the code will be invalidated.</p>
          </div>

          <div class="lcars-form-group">
            <label for="recoveryCode">Recovery Code</label>
            <input
              type="text"
              id="recoveryCode"
              name="recoveryCode"
              [(ngModel)]="recoveryCode"
              placeholder="XXXX-XXXX"
              autocomplete="off"
              [disabled]="submitting" />
          </div>

          <div class="lcars-actions">
            <button
              type="submit"
              class="lcars-button-primary"
              [disabled]="submitting || recoveryCode.length < 8">
              {{ submitting ? 'Verifying...' : 'Use Recovery Code' }}
            </button>
          </div>
        </form>

        <!-- Back to Login -->
        <div class="back-link">
          <a [routerLink]="['..', 'login']" [queryParams]="{ ReturnUrl: returnUrl }">
            Back to Login
          </a>
        </div>
      </app-lcars-panel>
    </div>
  `,
  styleUrl: './two-factor-login.component.scss'
})
export class TwoFactorLoginComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private authApi = inject(AuthApiService);

  // State
  submitting = false;
  sendingEmail = false;
  emailSent = false;
  errorMessage?: string;

  // Method selection
  activeMethod: TwoFactorMethod = 'totp';
  canUseTotp = true;
  canUseEmail = false;

  // Form data
  totpCode = '';
  emailCode = '';
  recoveryCode = '';
  rememberMachine = false;

  // Navigation
  returnUrl = '';
  tenantId = 'System';

  ngOnInit(): void {
    this.tenantId = this.route.snapshot.params['tenantId'] || 'System';
    // Support both 'ReturnUrl' (from IdentityServer) and 'returnUrl' (from Angular navigation)
    this.returnUrl = this.route.snapshot.queryParams['ReturnUrl']
                  || this.route.snapshot.queryParams['returnUrl']
                  || '';

    // Get capabilities from query params (set by login redirect)
    this.canUseTotp = this.route.snapshot.queryParams['totp'] !== 'false';
    this.canUseEmail = this.route.snapshot.queryParams['email'] === 'true';

    // Set default method based on capabilities
    if (this.canUseTotp) {
      this.activeMethod = 'totp';
    } else if (this.canUseEmail) {
      this.activeMethod = 'email';
    } else {
      this.activeMethod = 'recovery';
    }
  }

  setMethod(method: TwoFactorMethod): void {
    this.activeMethod = method;
    this.errorMessage = undefined;
  }

  onSubmitTotp(): void {
    this.submitting = true;
    this.errorMessage = undefined;

    this.authApi.loginTwoFactor({
      code: this.totpCode,
      rememberMachine: this.rememberMachine,
      returnUrl: this.returnUrl || undefined
    }).subscribe({
      next: (result) => this.handleResult(result),
      error: (error) => this.handleError(error)
    });
  }

  sendEmailCode(): void {
    this.sendingEmail = true;
    this.errorMessage = undefined;

    this.authApi.sendTwoFactorEmail().subscribe({
      next: (result) => {
        this.sendingEmail = false;
        if (result.success) {
          this.emailSent = true;
        } else {
          this.errorMessage = result.errorMessage || 'Failed to send email';
        }
      },
      error: (error) => {
        this.sendingEmail = false;
        this.errorMessage = error.error?.message || 'Failed to send email';
      }
    });
  }

  onSubmitEmail(): void {
    this.submitting = true;
    this.errorMessage = undefined;

    this.authApi.loginTwoFactorEmail({
      code: this.emailCode,
      rememberMachine: this.rememberMachine,
      returnUrl: this.returnUrl || undefined
    }).subscribe({
      next: (result) => this.handleResult(result),
      error: (error) => this.handleError(error)
    });
  }

  onSubmitRecovery(): void {
    this.submitting = true;
    this.errorMessage = undefined;

    this.authApi.loginRecovery({
      recoveryCode: this.recoveryCode,
      returnUrl: this.returnUrl || undefined
    }).subscribe({
      next: (result) => this.handleResult(result),
      error: (error) => this.handleError(error)
    });
  }

  private handleResult(result: { success: boolean; redirectUrl?: string; errorMessage?: string }): void {
    this.submitting = false;
    if (result.success) {
      // Use redirectUrl from result, or fall back to returnUrl, or manage page
      const redirectTo = result.redirectUrl || this.returnUrl;
      if (redirectTo) {
        window.location.href = redirectTo;
      } else {
        this.router.navigate(['/', this.tenantId, 'manage']);
      }
    } else {
      this.errorMessage = result.errorMessage || 'Verification failed';
    }
  }

  private handleError(error: any): void {
    this.submitting = false;
    this.errorMessage = error.error?.message || 'An error occurred';
  }
}
