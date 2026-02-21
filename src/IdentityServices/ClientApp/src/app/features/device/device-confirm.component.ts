import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ScopeListComponent } from '../../shared/components/scope-list/scope-list.component';
import { ConsentApiService } from '../../core/services/consent-api.service';
import { DeviceAuthorizationContext, ScopeItem } from '../../core/models/consent.models';

@Component({
  selector: 'app-device-confirm',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    LcarsPanelComponent,
    LcarsHeaderComponent,
    ScopeListComponent
  ],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header
          subtitle="Authorize Device">
        </app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">Verifying Code</span>
        </div>

        <ng-container *ngIf="!loading && context">
          <!-- Device Code Display -->
          <div class="device-code-display">
            <span class="device-code-label">Device Code</span>
            <span class="device-code-value">{{ userCode }}</span>
          </div>

          <!-- Client Info -->
          <div class="lcars-client-info" *ngIf="context.clientName">
            <div class="lcars-client-info__logo" *ngIf="context.clientLogoUrl">
              <img [src]="context.clientLogoUrl" [alt]="context.clientName" />
            </div>
            <div class="lcars-client-info__details">
              <span class="lcars-client-info__name">{{ context.clientName }}</span>
            </div>
          </div>

          <p class="consent-description">
            This device is requesting access to your account:
          </p>

          <!-- Scopes -->
          <app-scope-list
            *ngIf="context.identityScopes.length > 0"
            title="Personal Information"
            [scopes]="context.identityScopes">
          </app-scope-list>

          <app-scope-list
            *ngIf="context.apiScopes.length > 0"
            title="Application Access"
            [scopes]="context.apiScopes">
          </app-scope-list>

          <!-- Actions -->
          <div class="lcars-actions">
            <button
              type="button"
              class="lcars-button-primary"
              (click)="onAllow()"
              [disabled]="submitting">
              {{ submitting ? 'Processing...' : 'Allow' }}
            </button>
            <button
              type="button"
              class="lcars-button-error"
              (click)="onDeny()"
              [disabled]="submitting">
              Deny
            </button>
          </div>
        </ng-container>

        <div *ngIf="!loading && !context && !success" class="error-state">
          <div class="lcars-error-message">
            {{ errorMessage || 'Invalid or expired device code.' }}
          </div>
          <button
            type="button"
            class="lcars-button-outline"
            (click)="goBack()">
            Try Again
          </button>
        </div>

        <div *ngIf="success" class="success-state">
          <div class="lcars-success-message">
            Device authorized successfully! You can close this window.
          </div>
        </div>
      </app-lcars-panel>
    </div>
  `,
  styleUrl: './device-confirm.component.scss'
})
export class DeviceConfirmComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private consentApi = inject(ConsentApiService);

  loading = true;
  submitting = false;
  success = false;
  errorMessage?: string;
  context?: DeviceAuthorizationContext;
  userCode = '';

  ngOnInit(): void {
    this.userCode = this.route.snapshot.queryParams['userCode'] || '';

    if (!this.userCode) {
      this.loading = false;
      this.errorMessage = 'No device code provided.';
      return;
    }

    this.loadContext();
  }

  private loadContext(): void {
    this.consentApi.getDeviceAuthorizationContext(this.userCode).subscribe({
      next: (context) => {
        this.context = context;
        this.loading = false;
      },
      error: (error: HttpErrorResponse) => {
        // If 401 Unauthorized, redirect to login with return URL back to this page
        if (error.status === 401) {
          const tenantId = this.route.snapshot.params['tenantId'] || 'System';
          const returnUrl = `/${tenantId}/device/confirm?userCode=${encodeURIComponent(this.userCode)}`;
          this.router.navigate(['/', tenantId, 'login'], {
            queryParams: { returnUrl }
          });
          return;
        }

        this.loading = false;
        this.errorMessage = error.error?.message || 'Invalid or expired device code.';
      }
    });
  }

  onAllow(): void {
    if (!this.context) return;

    this.submitting = true;

    const scopesConsented = [
      ...this.context.identityScopes.filter(s => s.checked).map(s => s.name),
      ...this.context.apiScopes.filter(s => s.checked).map(s => s.name)
    ];

    this.consentApi.submitDeviceAuthorization({
      userCode: this.userCode,
      scopesConsented,
      rememberConsent: false
    }).subscribe({
      next: (result) => {
        this.submitting = false;
        if (result.success) {
          this.success = true;
          this.context = undefined;
        } else {
          this.errorMessage = result.errorMessage || 'Authorization failed';
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.message || 'An error occurred';
      }
    });
  }

  onDeny(): void {
    this.submitting = true;

    this.consentApi.denyDeviceAuthorization(this.userCode).subscribe({
      next: () => {
        this.goBack();
      },
      error: () => {
        this.submitting = false;
      }
    });
  }

  goBack(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'device']);
  }
}
