import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../../shared/components/lcars-header/lcars-header.component';
import { ManageApiService } from '../../../core/services/manage-api.service';
import { AuthenticatorSetup } from '../../../core/models/manage.models';

@Component({
  selector: 'app-authenticator-setup',
  standalone: true,
  imports: [CommonModule, FormsModule, TranslatePipe, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel [variant]="setupComplete ? 'success' : 'default'">
        <app-lcars-header [subtitle]="'AUTHENTICATOR_SETUP.SUBTITLE' | translate"></app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">{{ 'AUTHENTICATOR_SETUP.SETTING_UP' | translate }}</span>
        </div>

        <!-- Setup Complete - Show Recovery Codes -->
        <div *ngIf="setupComplete && recoveryCodes.length > 0" class="success-content">
          <div class="success-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
          </div>
          <p class="success-message">{{ 'AUTHENTICATOR_SETUP.ENABLED_MESSAGE' | translate }}</p>

          <div class="recovery-codes-section">
            <h3 class="section-title">{{ 'AUTHENTICATOR_SETUP.RECOVERY_TITLE' | translate }}</h3>
            <p class="warning-text">
              {{ 'AUTHENTICATOR_SETUP.RECOVERY_WARNING' | translate }}
            </p>

            <div class="recovery-codes">
              <code *ngFor="let code of recoveryCodes" class="recovery-code">{{ code }}</code>
            </div>

            <button type="button" class="lcars-button-outline copy-button" (click)="copyRecoveryCodes()">
              {{ (copied ? 'AUTHENTICATOR_SETUP.COPIED' : 'AUTHENTICATOR_SETUP.COPY_CODES') | translate }}
            </button>
          </div>

          <button type="button" class="lcars-button-primary" (click)="goToStatus()">
            {{ 'AUTHENTICATOR_SETUP.DONE' | translate }}
          </button>
        </div>

        <!-- Setup Form -->
        <ng-container *ngIf="!loading && !setupComplete && setup">
          <div class="setup-instructions">
            <p class="instruction-text">
              {{ 'AUTHENTICATOR_SETUP.SCAN_INSTRUCTIONS' | translate }}
            </p>
          </div>

          <div class="qr-section">
            <div class="qr-code">
              <img [src]="'data:image/png;base64,' + setup.qrCodeImage" [alt]="'AUTHENTICATOR_SETUP.QR_ALT' | translate" />
            </div>
          </div>

          <div class="manual-section">
            <p class="manual-text">
              {{ 'AUTHENTICATOR_SETUP.MANUAL_TEXT' | translate }}
            </p>
            <div class="shared-key">
              <code>{{ setup.sharedKey }}</code>
              <button type="button" class="copy-key-button" (click)="copySharedKey()">
                {{ (keyCopied ? 'AUTHENTICATOR_SETUP.COPIED' : 'AUTHENTICATOR_SETUP.COPY') | translate }}
              </button>
            </div>
          </div>

          <form (ngSubmit)="onVerify()" class="verify-form">
            <div *ngIf="errorMessage" class="lcars-error-message">
              {{ errorMessage }}
            </div>

            <div class="lcars-form-group">
              <label for="verificationCode">{{ 'AUTHENTICATOR_SETUP.CODE_LABEL' | translate }}</label>
              <input
                type="text"
                id="verificationCode"
                name="verificationCode"
                [(ngModel)]="verificationCode"
                placeholder="000000"
                maxlength="6"
                autocomplete="one-time-code"
                [disabled]="submitting" />
            </div>

            <div class="lcars-actions">
              <button
                type="submit"
                class="lcars-button-primary"
                [disabled]="submitting || verificationCode.length < 6">
                {{ (submitting ? 'COMMON.VERIFYING' : 'AUTHENTICATOR_SETUP.VERIFY_ENABLE') | translate }}
              </button>
              <button type="button" class="lcars-button-outline" (click)="goToStatus()" [disabled]="submitting">
                {{ 'COMMON.CANCEL' | translate }}
              </button>
            </div>
          </form>
        </ng-container>

        <div *ngIf="!loading && !setup && !setupComplete" class="lcars-error-message">
          {{ 'AUTHENTICATOR_SETUP.ERROR_SETUP' | translate }}
        </div>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './authenticator-setup.component.scss'
})
export class AuthenticatorSetupComponent implements OnInit {
  private manageApi = inject(ManageApiService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  private translate = inject(TranslateService);

  loading = true;
  submitting = false;
  setupComplete = false;
  errorMessage?: string;
  setup?: AuthenticatorSetup;
  verificationCode = '';
  recoveryCodes: string[] = [];
  copied = false;
  keyCopied = false;

  ngOnInit(): void {
    this.loadSetup();
  }

  private loadSetup(): void {
    this.loading = true;
    this.manageApi.setupAuthenticator().subscribe({
      next: (setup) => {
        this.setup = setup;
        this.loading = false;
      },
      error: () => {
        this.loading = false;
      }
    });
  }

  onVerify(): void {
    this.submitting = true;
    this.errorMessage = undefined;

    this.manageApi.verifyAuthenticator({ code: this.verificationCode }).subscribe({
      next: (result) => {
        this.submitting = false;
        if (result.success) {
          this.recoveryCodes = result.recoveryCodes;
          this.setupComplete = true;
        } else {
          this.errorMessage = result.errorMessage || this.translate.instant('AUTHENTICATOR_SETUP.ERROR_INVALID_CODE');
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.message || this.translate.instant('COMMON.ERROR_GENERIC');
      }
    });
  }

  copyRecoveryCodes(): void {
    const codesText = this.recoveryCodes.join('\n');
    navigator.clipboard.writeText(codesText).then(() => {
      this.copied = true;
      setTimeout(() => this.copied = false, 2000);
    });
  }

  copySharedKey(): void {
    if (this.setup) {
      navigator.clipboard.writeText(this.setup.sharedKey.replace(/\s/g, '')).then(() => {
        this.keyCopied = true;
        setTimeout(() => this.keyCopied = false, 2000);
      });
    }
  }

  goToStatus(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'manage', '2fa']);
  }
}
