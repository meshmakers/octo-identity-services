import { Component, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink, ActivatedRoute } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { AuthApiService } from '../../core/services/auth-api.service';

@Component({
  selector: 'app-forgot-password',
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
          [subtitle]="'FORGOT_PASSWORD.SUBTITLE' | translate"
          [showUserMenu]="false">
        </app-lcars-header>

        <!-- Success State -->
        <div *ngIf="submitted" class="success-message">
          <div class="success-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
          </div>
          <h3>{{ 'FORGOT_PASSWORD.CHECK_EMAIL_TITLE' | translate }}</h3>
          <p>{{ 'FORGOT_PASSWORD.CHECK_EMAIL_TEXT' | translate: { email: email } }}</p>
          <a [routerLink]="['/', tenantId, 'login']" class="lcars-button">
            {{ 'COMMON.BACK_TO_LOGIN' | translate }}
          </a>
        </div>

        <!-- Form State -->
        <form *ngIf="!submitted" (ngSubmit)="onSubmit()" class="lcars-form">
          <p class="form-description">
            {{ 'FORGOT_PASSWORD.DESCRIPTION' | translate }}
          </p>

          <div *ngIf="errorMessage" class="lcars-error-message">
            {{ errorMessage }}
          </div>

          <div class="lcars-form-group">
            <label class="lcars-label" for="email">{{ 'FORGOT_PASSWORD.EMAIL_LABEL' | translate }}</label>
            <input
              type="email"
              id="email"
              name="email"
              class="lcars-input"
              [(ngModel)]="email"
              [disabled]="submitting"
              required
              autocomplete="email"
              [placeholder]="'FORGOT_PASSWORD.EMAIL_PLACEHOLDER' | translate" />
          </div>

          <div class="lcars-form-actions">
            <button
              type="submit"
              class="lcars-button lcars-button--primary"
              [disabled]="submitting || !email">
              {{ (submitting ? 'COMMON.SENDING' : 'FORGOT_PASSWORD.SEND_LINK') | translate }}
            </button>
          </div>

          <div class="form-footer">
            <a [routerLink]="['/', tenantId, 'login']" class="back-link">
              {{ 'COMMON.BACK_TO_LOGIN' | translate }}
            </a>
          </div>
        </form>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styles: [`
    .form-description {
      color: var(--ash-blue);
      margin-bottom: var(--lcars-spacing-lg);
      text-align: center;
    }

    .success-message {
      text-align: center;
      padding: var(--lcars-spacing-xl) 0;
    }

    .success-message .success-icon {
      color: var(--octo-mint);
      margin-bottom: var(--lcars-spacing-lg);
    }

    .success-message h3 {
      color: var(--octo-mint);
      font-size: var(--lcars-font-size-lg);
      margin-bottom: var(--lcars-spacing-md);
      text-transform: uppercase;
    }

    .success-message p {
      color: var(--ash-blue);
      margin-bottom: var(--lcars-spacing-xl);
      line-height: 1.6;
    }

    .form-footer {
      text-align: center;
      margin-top: var(--lcars-spacing-lg);
    }

    .back-link {
      color: var(--neo-cyan);
      text-decoration: none;
      font-size: var(--lcars-font-size-sm);
    }

    .back-link:hover {
      text-decoration: underline;
    }
  `]
})
export class ForgotPasswordComponent {
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  private authApi = inject(AuthApiService);
  private translate = inject(TranslateService);

  email = '';
  submitting = false;
  submitted = false;
  errorMessage?: string;
  tenantId = 'System';

  constructor() {
    this.tenantId = this.route.snapshot.params['tenantId'] || 'System';
  }

  onSubmit(): void {
    if (!this.email) {
      this.errorMessage = this.translate.instant('FORGOT_PASSWORD.ERROR_ENTER_EMAIL');
      return;
    }

    this.submitting = true;
    this.errorMessage = undefined;

    this.authApi.forgotPassword({ email: this.email }).subscribe({
      next: () => {
        this.submitting = false;
        this.submitted = true;
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.errorMessage || this.translate.instant('FORGOT_PASSWORD.ERROR_GENERIC');
      }
    });
  }
}
