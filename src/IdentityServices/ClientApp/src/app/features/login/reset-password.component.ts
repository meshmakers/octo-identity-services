import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink, ActivatedRoute } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { AuthApiService } from '../../core/services/auth-api.service';

@Component({
  selector: 'app-reset-password',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    RouterLink,
    TranslatePipe,
    LcarsPanelComponent,
    LcarsHeaderComponent
  ],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header
          [subtitle]="'RESET_PASSWORD.SUBTITLE' | translate"
          [showUserMenu]="false">
        </app-lcars-header>

        <!-- Loading State -->
        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">{{ 'RESET_PASSWORD.VALIDATING' | translate }}</span>
        </div>

        <!-- Invalid Token State -->
        <div *ngIf="!loading && !tokenValid && !success" class="error-state">
          <div class="error-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="15" y1="9" x2="9" y2="15"></line>
              <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
          </div>
          <h3>{{ 'RESET_PASSWORD.INVALID_LINK_TITLE' | translate }}</h3>
          <p>{{ 'RESET_PASSWORD.INVALID_LINK_TEXT' | translate }}</p>
          <a [routerLink]="['/', tenantId, 'forgot-password']" class="lcars-button">
            {{ 'RESET_PASSWORD.REQUEST_NEW_LINK' | translate }}
          </a>
        </div>

        <!-- Success State -->
        <div *ngIf="success" class="success-message">
          <div class="success-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
          </div>
          <h3>{{ 'RESET_PASSWORD.SUCCESS_TITLE' | translate }}</h3>
          <p>{{ 'RESET_PASSWORD.SUCCESS_TEXT' | translate }}</p>
          <a [routerLink]="['/', tenantId, 'login']" class="lcars-button">
            {{ 'COMMON.SIGN_IN' | translate }}
          </a>
        </div>

        <!-- Form State -->
        <form *ngIf="!loading && tokenValid && !success" (ngSubmit)="onSubmit()" class="lcars-form">
          <div *ngIf="errorMessage" class="lcars-error-message">
            {{ errorMessage }}
          </div>

          <div *ngIf="errors && errors.length > 0" class="lcars-error-list">
            <ul>
              <li *ngFor="let error of errors">{{ error }}</li>
            </ul>
          </div>

          <div class="lcars-form-group">
            <label class="lcars-label" for="newPassword">{{ 'RESET_PASSWORD.NEW_PASSWORD' | translate }}</label>
            <input
              type="password"
              id="newPassword"
              name="newPassword"
              class="lcars-input"
              [(ngModel)]="newPassword"
              [disabled]="submitting"
              required
              autocomplete="new-password"
              [placeholder]="'RESET_PASSWORD.NEW_PASSWORD_PLACEHOLDER' | translate" />
          </div>

          <div class="lcars-form-group">
            <label class="lcars-label" for="confirmPassword">{{ 'RESET_PASSWORD.CONFIRM_PASSWORD' | translate }}</label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              class="lcars-input"
              [(ngModel)]="confirmPassword"
              [disabled]="submitting"
              required
              autocomplete="new-password"
              [placeholder]="'RESET_PASSWORD.CONFIRM_PASSWORD_PLACEHOLDER' | translate" />
          </div>

          <div *ngIf="passwordMismatch" class="field-error">
            {{ 'COMMON.PASSWORDS_MISMATCH' | translate }}
          </div>

          <div class="lcars-form-actions">
            <button
              type="submit"
              class="lcars-button lcars-button--primary"
              [disabled]="submitting || !newPassword || !confirmPassword">
              {{ (submitting ? 'RESET_PASSWORD.SUBMITTING' : 'RESET_PASSWORD.SUBMIT') | translate }}
            </button>
          </div>
        </form>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styles: [`
    .error-state, .success-message {
      text-align: center;
      padding: var(--lcars-spacing-xl) 0;
    }

    .error-state h3, .success-message h3 {
      font-size: var(--lcars-font-size-lg);
      margin-bottom: var(--lcars-spacing-md);
      text-transform: uppercase;
    }

    .error-state p, .success-message p {
      color: var(--ash-blue);
      margin-bottom: var(--lcars-spacing-xl);
      line-height: 1.6;
    }

    .error-state .error-icon {
      color: var(--error-red, #ff5252);
      margin-bottom: var(--lcars-spacing-lg);
    }

    .error-state h3 {
      color: var(--error-red, #ff5252);
    }

    .success-message .success-icon {
      color: var(--octo-mint);
      margin-bottom: var(--lcars-spacing-lg);
    }

    .success-message h3 {
      color: var(--octo-mint);
    }

    .lcars-error-list {
      background: rgba(255, 82, 82, 0.1);
      border: 1px solid var(--error-red, #ff5252);
      border-radius: var(--lcars-radius-sm);
      padding: var(--lcars-spacing-md);
      margin-bottom: var(--lcars-spacing-lg);
    }

    .lcars-error-list ul {
      margin: 0;
      padding-left: var(--lcars-spacing-lg);
      color: var(--error-red, #ff5252);
      font-size: var(--lcars-font-size-sm);
    }

    .field-error {
      color: var(--error-red, #ff5252);
      font-size: var(--lcars-font-size-sm);
      margin-top: calc(-1 * var(--lcars-spacing-sm));
      margin-bottom: var(--lcars-spacing-md);
    }
  `]
})
export class ResetPasswordComponent implements OnInit {
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  private authApi = inject(AuthApiService);
  private translate = inject(TranslateService);

  email = '';
  token = '';
  newPassword = '';
  confirmPassword = '';

  loading = true;
  tokenValid = false;
  submitting = false;
  success = false;
  errorMessage?: string;
  errors?: string[];
  tenantId = 'System';

  get passwordMismatch(): boolean {
    return this.confirmPassword.length > 0 && this.newPassword !== this.confirmPassword;
  }

  ngOnInit(): void {
    this.tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.email = this.route.snapshot.queryParams['email'] || '';
    this.token = this.route.snapshot.queryParams['token'] || '';

    if (!this.email || !this.token) {
      this.loading = false;
      this.tokenValid = false;
      return;
    }

    // Validate the token
    this.authApi.validateResetToken(this.email, this.token).subscribe({
      next: (result) => {
        this.loading = false;
        this.tokenValid = result.isValid;
      },
      error: () => {
        this.loading = false;
        this.tokenValid = false;
      }
    });
  }

  onSubmit(): void {
    if (!this.newPassword || !this.confirmPassword) {
      this.errorMessage = this.translate.instant('RESET_PASSWORD.ERROR_FILL_ALL');
      return;
    }

    if (this.newPassword !== this.confirmPassword) {
      this.errorMessage = this.translate.instant('COMMON.PASSWORDS_MISMATCH');
      return;
    }

    this.submitting = true;
    this.errorMessage = undefined;
    this.errors = undefined;

    this.authApi.resetPassword({
      email: this.email,
      token: this.token,
      newPassword: this.newPassword,
      confirmPassword: this.confirmPassword
    }).subscribe({
      next: (result) => {
        this.submitting = false;
        if (result.success) {
          this.success = true;
        } else {
          this.errorMessage = result.errorMessage;
          this.errors = result.errors;
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.errorMessage || this.translate.instant('RESET_PASSWORD.ERROR_GENERIC');
        this.errors = error.error?.errors;
      }
    });
  }
}
