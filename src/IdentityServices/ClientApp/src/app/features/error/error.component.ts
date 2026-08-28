import { Component, OnInit, inject, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ErrorContext } from '../../core/models/error.models';
import { AuthApiService } from '../../core/services/auth-api.service';

@Component({
  selector: 'app-error',
  standalone: true,
  imports: [CommonModule, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel variant="error">
        <app-lcars-header
          subtitle="Error">
        </app-lcars-header>

        <div class="error-content">
          <div class="error-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
          </div>

          <h2 class="error-title">{{ title }}</h2>

          <p class="error-message">{{ message }}</p>

          <p class="error-hint" *ngIf="hint">{{ hint }}</p>

          <details class="error-technical" *ngIf="hasTechnicalDetails">
            <summary>Technical details</summary>
            <div class="error-details" *ngIf="error.error">
              <span class="error-details__label">Error</span>
              <code class="error-details__value">{{ error.error }}</code>
            </div>
            <div class="error-details" *ngIf="error.errorDescription">
              <span class="error-details__label">Description</span>
              <code class="error-details__value">{{ error.errorDescription }}</code>
            </div>
            <div class="error-details" *ngIf="error.clientId">
              <span class="error-details__label">Application</span>
              <code class="error-details__value">{{ error.clientId }}</code>
            </div>
            <div class="error-details" *ngIf="error.requestId">
              <span class="error-details__label">Request ID</span>
              <code class="error-details__value">{{ error.requestId }}</code>
            </div>
            <div class="error-details" *ngIf="error.activityId">
              <span class="error-details__label">Activity ID</span>
              <code class="error-details__value">{{ error.activityId }}</code>
            </div>
          </details>

          <div class="lcars-actions">
            <a *ngIf="error.clientUrl" [href]="error.clientUrl" class="lcars-button-outline">
              Back to {{ error.clientName || 'application' }}
            </a>
            <a [href]="'/' + tenantId + '/login'" class="lcars-button-outline">
              Back to Sign In
            </a>
          </div>
        </div>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './error.component.scss'
})
export class ErrorComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private authApi = inject(AuthApiService);
  private cdr = inject(ChangeDetectorRef);

  error: ErrorContext = {};

  get tenantId(): string {
    return this.route.snapshot.params['tenantId'] || 'System';
  }

  get title(): string {
    switch (this.error.kind) {
      case 'clientNotRegistered':
        return 'Application not available here';
      case 'invalidRedirectUri':
        return 'Application configuration problem';
      default:
        return 'Something went wrong';
    }
  }

  get message(): string {
    const app = this.error.clientName || this.error.clientId || 'The application';
    switch (this.error.kind) {
      case 'clientNotRegistered':
        // Registered-but-disabled and never-registered are indistinguishable from
        // here, so the copy names both rather than guessing.
        return `${app} is not registered, or not enabled, for the workspace "${this.tenantId}".`;
      case 'invalidRedirectUri':
        return `${app} sent a return address that is not registered for it in this workspace.`;
      default:
        return this.error.errorMessage || 'An unexpected error occurred.';
    }
  }

  get hint(): string | null {
    switch (this.error.kind) {
      case 'clientNotRegistered':
      case 'invalidRedirectUri':
        return 'This is a configuration issue, not something you can fix by signing in again — please pass the details below to your administrator.';
      default:
        return null;
    }
  }

  get hasTechnicalDetails(): boolean {
    return !!(this.error.error || this.error.errorDescription || this.error.clientId
      || this.error.requestId || this.error.activityId);
  }

  ngOnInit(): void {
    const queryParams = this.route.snapshot.queryParams;

    // The external-login callback redirects with readable query parameters; the
    // authorize endpoint only ever passes an opaque errorId, which has to be
    // resolved server-side.
    this.error = {
      requestId: queryParams['requestId'],
      errorMessage: queryParams['error'] || queryParams['errorMessage'],
      errorDescription: queryParams['error_description'] || queryParams['errorDescription']
    };

    const errorId = queryParams['errorId'];
    if (errorId) {
      this.authApi.getErrorContext(errorId).subscribe({
        next: (context) => {
          // Keep whatever the query parameters carried; the resolved context wins.
          this.error = { ...this.error, ...context };
          this.applyMessageFallback();
          this.cdr.markForCheck();
        },
        // A failed lookup must not replace the page with nothing — fall back to
        // the generic text the query parameters already produced.
        error: () => {
          this.applyMessageFallback();
          this.cdr.markForCheck();
        }
      });
      return;
    }

    this.applyMessageFallback();
  }

  private applyMessageFallback(): void {
    if (!this.error.errorMessage) {
      this.error.errorMessage = 'An unexpected error occurred.';
    }
  }
}
