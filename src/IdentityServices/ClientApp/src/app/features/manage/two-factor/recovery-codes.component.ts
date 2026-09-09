import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, ActivatedRoute } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../../shared/components/lcars-header/lcars-header.component';
import { ManageApiService } from '../../../core/services/manage-api.service';

@Component({
  selector: 'app-recovery-codes',
  standalone: true,
  imports: [CommonModule, TranslatePipe, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header [subtitle]="'RECOVERY_CODES.SUBTITLE' | translate"></app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">{{ 'RECOVERY_CODES.GENERATING' | translate }}</span>
        </div>

        <ng-container *ngIf="!loading && recoveryCodes.length > 0">
          <div class="warning-section">
            <div class="warning-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
              </svg>
            </div>
            <p class="warning-text">
              <strong>{{ 'RECOVERY_CODES.WARNING_TITLE' | translate }}</strong><br>
              {{ 'RECOVERY_CODES.WARNING_TEXT' | translate }}
            </p>
          </div>

          <div class="recovery-codes">
            <code *ngFor="let code of recoveryCodes" class="recovery-code">{{ code }}</code>
          </div>

          <div class="lcars-actions">
            <button type="button" class="lcars-button-primary" (click)="copyRecoveryCodes()">
              {{ (copied ? 'RECOVERY_CODES.COPIED' : 'RECOVERY_CODES.COPY_ALL') | translate }}
            </button>
            <button type="button" class="lcars-button-outline" (click)="downloadCodes()">
              {{ 'RECOVERY_CODES.DOWNLOAD' | translate }}
            </button>
            <button type="button" class="lcars-button-outline" (click)="goBack()">
              {{ 'RECOVERY_CODES.BACK_TO_2FA' | translate }}
            </button>
          </div>
        </ng-container>

        <div *ngIf="!loading && recoveryCodes.length === 0 && !errorMessage" class="info-section">
          <p class="info-text">
            {{ 'RECOVERY_CODES.EMPTY' | translate }}
          </p>
          <button type="button" class="lcars-button-outline" (click)="goBack()">
            {{ 'RECOVERY_CODES.BACK_TO_2FA' | translate }}
          </button>
        </div>

        <div *ngIf="errorMessage" class="lcars-error-message">
          {{ errorMessage }}
          <div class="lcars-actions">
            <button type="button" class="lcars-button-outline" (click)="goBack()">
              {{ 'RECOVERY_CODES.BACK_TO_2FA' | translate }}
            </button>
          </div>
        </div>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './recovery-codes.component.scss'
})
export class RecoveryCodesComponent implements OnInit {
  private manageApi = inject(ManageApiService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  private translate = inject(TranslateService);

  loading = false;
  recoveryCodes: string[] = [];
  errorMessage?: string;
  copied = false;

  ngOnInit(): void {
    const shouldGenerate = this.route.snapshot.queryParams['generate'] === 'true';
    if (shouldGenerate) {
      this.generateCodes();
    }
  }

  private generateCodes(): void {
    this.loading = true;
    this.errorMessage = undefined;

    this.manageApi.generateRecoveryCodes().subscribe({
      next: (result) => {
        this.recoveryCodes = result.recoveryCodes;
        this.loading = false;
      },
      error: (error) => {
        this.loading = false;
        this.errorMessage = error.error?.message || this.translate.instant('RECOVERY_CODES.ERROR_GENERATE');
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

  downloadCodes(): void {
    const codesText = [
      this.translate.instant('RECOVERY_CODES.FILE_TITLE'),
      '========================',
      '',
      this.translate.instant('RECOVERY_CODES.FILE_STORE'),
      this.translate.instant('RECOVERY_CODES.FILE_ONCE'),
      '',
      ...this.recoveryCodes,
      '',
      this.translate.instant('RECOVERY_CODES.FILE_GENERATED') + ' ' + new Date().toISOString()
    ].join('\n');

    const blob = new Blob([codesText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'octomesh-recovery-codes.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  goBack(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'manage', '2fa']);
  }
}
