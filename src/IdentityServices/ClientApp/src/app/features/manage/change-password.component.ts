import { Component, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ManageApiService } from '../../core/services/manage-api.service';
import { ChangePasswordRequest } from '../../core/models/manage.models';

@Component({
  selector: 'app-change-password',
  standalone: true,
  imports: [CommonModule, FormsModule, TranslatePipe, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel [variant]="success ? 'success' : 'default'">
        <app-lcars-header
          [subtitle]="'CHANGE_PASSWORD.SUBTITLE' | translate">
        </app-lcars-header>

        <div *ngIf="success" class="success-content">
          <div class="success-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
          </div>
          <p class="success-message">{{ 'CHANGE_PASSWORD.SUCCESS' | translate }}</p>
          <button type="button" class="lcars-button-outline" (click)="goBack()">
            {{ 'COMMON.BACK_TO_PROFILE' | translate }}
          </button>
        </div>

        <form *ngIf="!success" (ngSubmit)="onSubmit()" #passwordForm="ngForm">
          <div *ngIf="errorMessage" class="lcars-error-message">
            {{ errorMessage }}
          </div>

          <div *ngIf="errors.length > 0" class="lcars-error-message">
            <ul>
              <li *ngFor="let error of errors">{{ error }}</li>
            </ul>
          </div>

          <div class="lcars-form-group">
            <label for="currentPassword">{{ 'CHANGE_PASSWORD.CURRENT' | translate }}</label>
            <input
              type="password"
              id="currentPassword"
              name="currentPassword"
              [(ngModel)]="model.currentPassword"
              required
              autocomplete="current-password"
              [disabled]="submitting" />
          </div>

          <div class="lcars-form-group">
            <label for="newPassword">{{ 'CHANGE_PASSWORD.NEW' | translate }}</label>
            <input
              type="password"
              id="newPassword"
              name="newPassword"
              [(ngModel)]="model.newPassword"
              required
              minlength="8"
              autocomplete="new-password"
              [disabled]="submitting" />
          </div>

          <div class="lcars-form-group">
            <label for="confirmPassword">{{ 'CHANGE_PASSWORD.CONFIRM' | translate }}</label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              [(ngModel)]="model.confirmPassword"
              required
              autocomplete="new-password"
              [disabled]="submitting" />
          </div>

          <div *ngIf="model.newPassword && model.confirmPassword && model.newPassword !== model.confirmPassword"
               class="validation-error">
            {{ 'COMMON.PASSWORDS_MISMATCH' | translate }}
          </div>

          <div class="lcars-actions">
            <button
              type="submit"
              class="lcars-button-primary"
              [disabled]="submitting || !model.currentPassword || !model.newPassword || model.newPassword !== model.confirmPassword">
              {{ (submitting ? 'CHANGE_PASSWORD.SUBMITTING' : 'CHANGE_PASSWORD.SUBMIT') | translate }}
            </button>
            <button type="button" class="lcars-button-outline" (click)="goBack()" [disabled]="submitting">
              {{ 'COMMON.CANCEL' | translate }}
            </button>
          </div>
        </form>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './change-password.component.scss'
})
export class ChangePasswordComponent {
  private manageApi = inject(ManageApiService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  private translate = inject(TranslateService);

  submitting = false;
  success = false;
  errorMessage?: string;
  errors: string[] = [];

  model: ChangePasswordRequest = {
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  };

  onSubmit(): void {
    if (this.model.newPassword !== this.model.confirmPassword) {
      this.errorMessage = this.translate.instant('COMMON.PASSWORDS_MISMATCH');
      return;
    }

    this.submitting = true;
    this.errorMessage = undefined;
    this.errors = [];

    this.manageApi.changePassword(this.model).subscribe({
      next: (result) => {
        this.submitting = false;
        if (result.success) {
          this.success = true;
        } else {
          this.errorMessage = result.errorMessage;
          this.errors = result.errors || [];
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.message || this.translate.instant('COMMON.ERROR_GENERIC');
      }
    });
  }

  goBack(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'manage']);
  }
}
