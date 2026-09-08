import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute, RouterLink } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../../shared/components/lcars-header/lcars-header.component';
import { ManageApiService } from '../../../core/services/manage-api.service';
import { TwoFactorStatus } from '../../../core/models/manage.models';

@Component({
  selector: 'app-two-factor-status',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, TranslatePipe, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header [subtitle]="'TWO_FACTOR.SUBTITLE' | translate"></app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">{{ 'COMMON.LOADING' | translate }}</span>
        </div>

        <ng-container *ngIf="!loading && status">
          <div class="status-section">
            <div class="status-item">
              <span class="status-item__label">{{ 'TWO_FACTOR.STATUS' | translate }}</span>
              <span class="status-item__value">
                <span class="status-badge" [class.status-badge--success]="status.enabled" [class.status-badge--warning]="!status.enabled">
                  {{ (status.enabled ? 'TWO_FACTOR.ENABLED' : 'TWO_FACTOR.DISABLED') | translate }}
                </span>
              </span>
            </div>

            <div class="status-item" *ngIf="status.enabled">
              <span class="status-item__label">{{ 'TWO_FACTOR.AUTHENTICATOR_APP' | translate }}</span>
              <span class="status-item__value">
                <span class="status-badge" [class.status-badge--success]="status.hasAuthenticator">
                  {{ (status.hasAuthenticator ? 'TWO_FACTOR.CONFIGURED' : 'TWO_FACTOR.NOT_CONFIGURED') | translate }}
                </span>
              </span>
            </div>

            <div class="status-item" *ngIf="status.enabled">
              <span class="status-item__label">{{ 'TWO_FACTOR.RECOVERY_CODES' | translate }}</span>
              <span class="status-item__value">
                <span class="status-badge" [class.status-badge--warning]="status.recoveryCodesLeft <= 3" [class.status-badge--success]="status.recoveryCodesLeft > 3">
                  {{ 'TWO_FACTOR.REMAINING' | translate: { count: status.recoveryCodesLeft } }}
                </span>
              </span>
            </div>
          </div>

          <div class="info-section" *ngIf="!status.enabled">
            <p class="info-text">
              {{ 'TWO_FACTOR.INFO' | translate }}
            </p>
          </div>

          <!-- Disable 2FA Form -->
          <div *ngIf="status.enabled && showDisableForm" class="disable-section">
            <div *ngIf="errorMessage" class="lcars-error-message">
              {{ errorMessage }}
            </div>

            <div class="lcars-form-group">
              <label for="disableCode">{{ 'TWO_FACTOR.DISABLE_CODE_LABEL' | translate }}</label>
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
                {{ (submitting ? 'TWO_FACTOR.DISABLING' : 'TWO_FACTOR.DISABLE') | translate }}
              </button>
              <button type="button" class="lcars-button-outline" (click)="showDisableForm = false" [disabled]="submitting">
                {{ 'COMMON.CANCEL' | translate }}
              </button>
            </div>
          </div>

          <!-- Actions when not showing disable form -->
          <div class="lcars-actions" *ngIf="!showDisableForm">
            <a *ngIf="!status.enabled" routerLink="setup" class="lcars-button-primary">
              {{ 'TWO_FACTOR.ENABLE' | translate }}
            </a>

            <button *ngIf="status.enabled && status.recoveryCodesLeft <= 3" type="button" class="lcars-button-warning" (click)="onGenerateRecoveryCodes()">
              {{ 'TWO_FACTOR.GENERATE_NEW_CODES' | translate }}
            </button>

            <button *ngIf="status.enabled" type="button" class="lcars-button-outline" (click)="showDisableForm = true">
              {{ 'TWO_FACTOR.DISABLE' | translate }}
            </button>

            <button type="button" class="lcars-button-outline" (click)="goBack()">
              {{ 'COMMON.BACK_TO_PROFILE' | translate }}
            </button>
          </div>
        </ng-container>

        <div *ngIf="!loading && !status" class="lcars-error-message">
          {{ 'TWO_FACTOR.ERROR_LOAD_STATUS' | translate }}
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
  private translate = inject(TranslateService);

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
          this.errorMessage = result.errorMessage || this.translate.instant('TWO_FACTOR.ERROR_DISABLE');
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.message || this.translate.instant('COMMON.ERROR_GENERIC');
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
