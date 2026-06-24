import { Component, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ManageApiService } from '../../core/services/manage-api.service';
import { ChangePasswordRequest } from '../../core/models/manage.models';

@Component({
  selector: 'app-change-password',
  standalone: true,
  imports: [CommonModule, FormsModule, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel [variant]="success ? 'success' : 'default'">
        <app-lcars-header
          subtitle="Change Password">
        </app-lcars-header>

        <div *ngIf="success" class="success-content">
          <div class="success-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
          </div>
          <p class="success-message">Your password has been changed successfully.</p>
          <button type="button" class="lcars-button-outline" (click)="goBack()">
            Back to Profile
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
            <label for="currentPassword">Current Password</label>
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
            <label for="newPassword">New Password</label>
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
            <label for="confirmPassword">Confirm Password</label>
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
            Passwords do not match
          </div>

          <div class="lcars-actions">
            <button
              type="submit"
              class="lcars-button-primary"
              [disabled]="submitting || !model.currentPassword || !model.newPassword || model.newPassword !== model.confirmPassword">
              {{ submitting ? 'Changing...' : 'Change Password' }}
            </button>
            <button type="button" class="lcars-button-outline" (click)="goBack()" [disabled]="submitting">
              Cancel
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
      this.errorMessage = 'Passwords do not match';
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
        this.errorMessage = error.error?.message || 'An error occurred';
      }
    });
  }

  goBack(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'manage']);
  }
}
