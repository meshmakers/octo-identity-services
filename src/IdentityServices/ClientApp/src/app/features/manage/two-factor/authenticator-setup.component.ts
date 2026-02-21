import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { LcarsPanelComponent } from '../../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../../shared/components/lcars-header/lcars-header.component';
import { ManageApiService } from '../../../core/services/manage-api.service';
import { AuthenticatorSetup } from '../../../core/models/manage.models';

@Component({
  selector: 'app-authenticator-setup',
  standalone: true,
  imports: [CommonModule, FormsModule, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel [variant]="setupComplete ? 'success' : 'default'">
        <app-lcars-header subtitle="Setup Authenticator App"></app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">Setting up</span>
        </div>

        <!-- Setup Complete - Show Recovery Codes -->
        <div *ngIf="setupComplete && recoveryCodes.length > 0" class="success-content">
          <div class="success-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
          </div>
          <p class="success-message">Two-Factor Authentication is now enabled!</p>

          <div class="recovery-codes-section">
            <h3 class="section-title">Recovery Codes</h3>
            <p class="warning-text">
              Save these recovery codes in a secure location.
              You will only see them once!
            </p>

            <div class="recovery-codes">
              <code *ngFor="let code of recoveryCodes" class="recovery-code">{{ code }}</code>
            </div>

            <button type="button" class="lcars-button-outline copy-button" (click)="copyRecoveryCodes()">
              {{ copied ? 'Copied!' : 'Copy Codes' }}
            </button>
          </div>

          <button type="button" class="lcars-button-primary" (click)="goToStatus()">
            Done
          </button>
        </div>

        <!-- Setup Form -->
        <ng-container *ngIf="!loading && !setupComplete && setup">
          <div class="setup-instructions">
            <p class="instruction-text">
              Scan this QR code with your authenticator app (like Google Authenticator, Authy, or Microsoft Authenticator).
            </p>
          </div>

          <div class="qr-section">
            <div class="qr-code">
              <img [src]="'data:image/png;base64,' + setup.qrCodeImage" alt="QR Code for Authenticator App" />
            </div>
          </div>

          <div class="manual-section">
            <p class="manual-text">
              Can't scan the QR code? Enter this key manually:
            </p>
            <div class="shared-key">
              <code>{{ setup.sharedKey }}</code>
              <button type="button" class="copy-key-button" (click)="copySharedKey()">
                {{ keyCopied ? 'Copied!' : 'Copy' }}
              </button>
            </div>
          </div>

          <form (ngSubmit)="onVerify()" class="verify-form">
            <div *ngIf="errorMessage" class="lcars-error-message">
              {{ errorMessage }}
            </div>

            <div class="lcars-form-group">
              <label for="verificationCode">Enter the 6-digit code from your app</label>
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
                {{ submitting ? 'Verifying...' : 'Verify and Enable' }}
              </button>
              <button type="button" class="lcars-button-outline" (click)="goToStatus()" [disabled]="submitting">
                Cancel
              </button>
            </div>
          </form>
        </ng-container>

        <div *ngIf="!loading && !setup && !setupComplete" class="lcars-error-message">
          Failed to setup authenticator. Please try again.
        </div>
      </app-lcars-panel>
    </div>
  `,
  styleUrl: './authenticator-setup.component.scss'
})
export class AuthenticatorSetupComponent implements OnInit {
  private manageApi = inject(ManageApiService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);

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
          this.errorMessage = result.errorMessage || 'Invalid verification code';
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.message || 'An error occurred';
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
