import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ErrorContext } from '../../core/models/error.models';

@Component({
  selector: 'app-error',
  standalone: true,
  imports: [CommonModule, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel variant="error">
        <app-lcars-header
          primaryText="OCTO"
          secondaryText="IDENTITY"
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

          <h2 class="error-title">Something went wrong</h2>

          <p class="error-message" *ngIf="error.errorMessage">
            {{ error.errorMessage }}
          </p>

          <p class="error-description" *ngIf="error.errorDescription">
            {{ error.errorDescription }}
          </p>

          <div class="error-details" *ngIf="error.requestId">
            <span class="error-details__label">Request ID</span>
            <code class="error-details__value">{{ error.requestId }}</code>
          </div>

          <div class="lcars-actions">
            <a [href]="'/' + tenantId + '/login'" class="lcars-button-outline">
              Back to Sign In
            </a>
          </div>
        </div>
      </app-lcars-panel>
    </div>
  `,
  styleUrl: './error.component.scss'
})
export class ErrorComponent implements OnInit {
  private route = inject(ActivatedRoute);

  error: ErrorContext = {};

  get tenantId(): string {
    return this.route.snapshot.params['tenantId'] || 'System';
  }

  ngOnInit(): void {
    const queryParams = this.route.snapshot.queryParams;
    this.error = {
      requestId: queryParams['requestId'],
      errorMessage: queryParams['error'] || queryParams['errorMessage'],
      errorDescription: queryParams['error_description'] || queryParams['errorDescription']
    };

    // Default message if none provided
    if (!this.error.errorMessage) {
      this.error.errorMessage = 'An unexpected error occurred.';
    }
  }
}
