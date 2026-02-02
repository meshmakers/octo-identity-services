import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink, ActivatedRoute } from '@angular/router';
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
    LcarsPanelComponent,
    LcarsHeaderComponent
  ],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header
          subtitle="Reset your password"
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
          <h3>Check your email</h3>
          <p>If an account exists with {{ email }}, you will receive a password reset link shortly.</p>
          <a [routerLink]="['/', tenantId, 'login']" class="lcars-button">
            Back to Login
          </a>
        </div>

        <!-- Form State -->
        <form *ngIf="!submitted" (ngSubmit)="onSubmit()" class="lcars-form">
          <p class="form-description">
            Enter your email address and we'll send you a link to reset your password.
          </p>

          <div *ngIf="errorMessage" class="lcars-error-message">
            {{ errorMessage }}
          </div>

          <div class="lcars-form-group">
            <label class="lcars-label" for="email">Email Address</label>
            <input
              type="email"
              id="email"
              name="email"
              class="lcars-input"
              [(ngModel)]="email"
              [disabled]="submitting"
              required
              autocomplete="email"
              placeholder="Enter your email" />
          </div>

          <div class="lcars-form-actions">
            <button
              type="submit"
              class="lcars-button lcars-button--primary"
              [disabled]="submitting || !email">
              {{ submitting ? 'Sending...' : 'Send Reset Link' }}
            </button>
          </div>

          <div class="form-footer">
            <a [routerLink]="['/', tenantId, 'login']" class="back-link">
              Back to Login
            </a>
          </div>
        </form>
      </app-lcars-panel>
    </div>
  `,
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
      this.errorMessage = 'Please enter your email address';
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
        this.errorMessage = error.error?.errorMessage || 'An error occurred. Please try again.';
      }
    });
  }
}
