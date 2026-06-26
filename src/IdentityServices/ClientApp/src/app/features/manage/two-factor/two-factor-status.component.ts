import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute, RouterLink } from '@angular/router';
import { LcarsPanelComponent } from '../../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../../shared/components/lcars-header/lcars-header.component';
import { ManageApiService } from '../../../core/services/manage-api.service';
import { TwoFactorStatus } from '../../../core/models/manage.models';

@Component({
  selector: 'app-two-factor-status',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header subtitle="Two-Factor Authentication"></app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">Loading</span>
        </div>

        <ng-container *ngIf="!loading && status">
          <div class="status-section">
            <div class="status-item">
              <span class="status-item__label">Status</span>
              <span class="status-item__value">
                <span class="status-badge" [class.status-badge--success]="status.enabled" [class.status-badge--warning]="!status.enabled">
                  {{ status.enabled ? 'Enabled' : 'Disabled' }}
                </span>
              </span>
            </div>

            <div class="status-item" *ngIf="status.enabled">
              <span class="status-item__label">Authenticator App</span>
              <span class="status-item__value">
                <span class="status-badge" [class.status-badge--success]="status.hasAuthenticator">
                  {{ status.hasAuthenticator ? 'Configured' : 'Not Configured' }}
                </span>
              </span>
            </div>

            <div class="status-item" *ngIf="status.enabled">
              <span class="status-item__label">Recovery Codes</span>
              <span class="status-item__value">
                <span class="status-badge" [class.status-badge--warning]="status.recoveryCodesLeft <= 3" [class.status-badge--success]="status.recoveryCodesLeft > 3">
                  {{ status.recoveryCodesLeft }} remaining
                </span>
              </span>
            </div>
          </div>

          <div class="info-section" *ngIf="!status.enabled">
            <p class="info-text">
              Two-factor authentication adds an extra layer of security to your account.
              When enabled, you'll need to enter a code from your authenticator app in addition to your password.
            </p>
          </div>

          <!-- Disable 2FA Form -->
          <div *ngIf="status.enabled && showDisableForm" class="disable-section">
            <div *ngIf="errorMessage" class="lcars-error-message">
              {{ errorMessage }}
            </div>

            <div class="lcars-form-group">
              <label for="disableCode">Enter authenticator code to disable 2FA</label>
              <input
                type="text"
                id="disableCode"
                name="disableCode"
                [(ngModel)]="disableCode"
                placeholder="000000"
                maxlength="6"
                autocomplete="one-time-code"
                [disabled]="submitting" />
            </div>

            <div class="lcars-actions">
              <button
                type="button"
                class="lcars-button-danger"
                [disabled]="submitting || disableCode.length < 6"
                (click)="onDisableTwoFactor()">
                {{ submitting ? 'Disabling...' : 'Disable Two-Factor Auth' }}
              </button>
              <button type="button" class="lcars-button-outline" (click)="showDisableForm = false" [disabled]="submitting">
                Cancel
              </button>
            </div>
          </div>

          <!-- Actions when not showing disable form -->
          <div class="lcars-actions" *ngIf="!showDisableForm">
            <a *ngIf="!status.enabled" routerLink="setup" class="lcars-button-primary">
              Enable Two-Factor Authentication
            </a>

            <button *ngIf="status.enabled && status.recoveryCodesLeft <= 3" type="button" class="lcars-button-warning" (click)="onGenerateRecoveryCodes()">
              Generate New Recovery Codes
            </button>

            <button *ngIf="status.enabled" type="button" class="lcars-button-outline" (click)="showDisableForm = true">
              Disable Two-Factor Auth
            </button>

            <button type="button" class="lcars-button-outline" (click)="goBack()">
              Back to Profile
            </button>
          </div>
        </ng-container>

        <div *ngIf="!loading && !status" class="lcars-error-message">
          Failed to load two-factor status. Please try again.
        </div>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './two-factor-status.component.scss'
})
export class TwoFactorStatusComponent implements OnInit {
  private manageApi = inject(ManageApiService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);

  loading = true;
  submitting = false;
  status?: TwoFactorStatus;
  errorMessage?: string;
  showDisableForm = false;
  disableCode = '';

  ngOnInit(): void {
    this.loadStatus();
  }

  private loadStatus(): void {
    this.loading = true;
    this.manageApi.getTwoFactorStatus().subscribe({
      next: (status) => {
        this.status = status;
        this.loading = false;
      },
      error: () => {
        this.loading = false;
      }
    });
  }

  onDisableTwoFactor(): void {
    this.submitting = true;
    this.errorMessage = undefined;

    this.manageApi.disableTwoFactor({ code: this.disableCode }).subscribe({
      next: (result) => {
        this.submitting = false;
        if (result.success) {
          this.showDisableForm = false;
          this.disableCode = '';
          this.loadStatus();
        } else {
          this.errorMessage = result.errorMessage || 'Failed to disable two-factor authentication';
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.message || 'An error occurred';
      }
    });
  }

  onGenerateRecoveryCodes(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'manage', '2fa', 'recovery-codes'], {
      queryParams: { generate: 'true' }
    });
  }

  goBack(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'manage']);
  }
}
