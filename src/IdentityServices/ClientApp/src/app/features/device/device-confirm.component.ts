import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ScopeListComponent } from '../../shared/components/scope-list/scope-list.component';
import { ConsentApiService } from '../../core/services/consent-api.service';
import { DeviceAuthorizationContext, DeviceAuthorizationResult } from '../../core/models/consent.models';

@Component({
  selector: 'app-device-confirm',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    TranslatePipe,
    LcarsPanelComponent,
    LcarsHeaderComponent,
    ScopeListComponent
  ],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header
          [subtitle]="'DEVICE.CONFIRM_SUBTITLE' | translate">
        </app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">{{ 'DEVICE.VERIFYING_CODE' | translate }}</span>
        </div>

        <ng-container *ngIf="!loading && context">
          <!-- Device Code Display -->
          <div class="device-code-display">
            <span class="device-code-label">{{ 'DEVICE.CODE_LABEL' | translate }}</span>
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

          <!-- Target tenant and signed-in account (AB#7959, RFC 8628 §5.4): a request that is not yours is recognisable -->
          <dl class="device-target" *ngIf="context.tenantId || context.accountUserName || context.accountEmail">
            <ng-container *ngIf="context.tenantId">
              <dt class="device-target__label">{{ 'DEVICE.TARGET_TENANT' | translate }}</dt>
              <dd class="device-target__value" data-test="device-target-tenant">{{ context.tenantId }}</dd>
            </ng-container>
            <ng-container *ngIf="context.accountUserName || context.accountEmail">
              <dt class="device-target__label">{{ 'DEVICE.SIGNED_IN_AS' | translate }}</dt>
              <dd class="device-target__value" data-test="device-target-account">
                {{ context.accountUserName || context.accountEmail }}
                <span class="device-target__secondary"
                      *ngIf="context.accountEmail && context.accountUserName && context.accountEmail !== context.accountUserName">
                  ({{ context.accountEmail }})
                </span>
              </dd>
            </ng-container>
          </dl>
          <p class="device-target__hint" *ngIf="context.tenantId">
            {{ 'DEVICE.CHECK_TARGET' | translate }}
          </p>

          <p class="consent-description">
            {{ 'DEVICE.REQUESTING_ACCESS' | translate }}
          </p>

          <!-- Scopes -->
          <app-scope-list
            *ngIf="context.identityScopes.length > 0"
            [title]="'CONSENT.IDENTITY_SCOPES' | translate"
            [scopes]="context.identityScopes">
          </app-scope-list>

          <app-scope-list
            *ngIf="context.apiScopes.length > 0"
            [title]="'CONSENT.API_SCOPES' | translate"
            [scopes]="context.apiScopes">
          </app-scope-list>

          <!-- Feedback of a failed Allow/Deny while the dialog is still usable (AB#7090) -->
          <div *ngIf="errorMessage" class="error-state" role="alert">
            <div class="lcars-error-message">{{ errorMessage }}</div>
          </div>

          <!-- Actions -->
          <div class="lcars-actions">
            <button
              type="button"
              class="lcars-button-primary"
              (click)="onAllow()"
              [disabled]="submitting">
              {{ (submitting ? 'COMMON.PROCESSING' : 'COMMON.ALLOW') | translate }}
            </button>
            <button
              type="button"
              class="lcars-button-error"
              (click)="onDeny()"
              [disabled]="submitting">
              {{ 'COMMON.DENY' | translate }}
            </button>
          </div>
        </ng-container>

        <div *ngIf="!loading && !context && !success && !denied" class="error-state" role="alert">
          <div class="lcars-error-message">
            {{ errorMessage || ('DEVICE.INVALID_CODE' | translate) }}
          </div>
          <button
            type="button"
            class="lcars-button-outline"
            (click)="goBack()">
            {{ 'COMMON.TRY_AGAIN' | translate }}
          </button>
        </div>

        <div *ngIf="success" class="success-state" role="status">
          <div class="lcars-success-message">
            {{ 'DEVICE.SUCCESS' | translate }}
          </div>
        </div>

        <div *ngIf="denied" class="success-state" role="status">
          <div class="lcars-success-message">
            {{ 'DEVICE.DENIED' | translate }}
          </div>
        </div>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './device-confirm.component.scss'
})
export class DeviceConfirmComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private consentApi = inject(ConsentApiService);
  private translate = inject(TranslateService);

  loading = true;
  submitting = false;
  success = false;
  denied = false;
  errorMessage?: string;
  context?: DeviceAuthorizationContext;
  userCode = '';
  private loginAlreadyAttempted = false;

  /** Query marker added to the returnUrl of the one login round trip. */
  private static readonly loginAttemptedParam = 'loginAttempted';

  ngOnInit(): void {
    this.userCode = this.route.snapshot.queryParams['userCode'] || '';
    this.loginAlreadyAttempted =
      this.route.snapshot.queryParams[DeviceConfirmComponent.loginAttemptedParam] === '1';

    if (!this.userCode) {
      this.loading = false;
      this.errorMessage = this.translate.instant('DEVICE.NO_CODE');
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
        // 401: the verification endpoint rejected the session cookie. Send the user to the login
        // page once, with a marker in the return URL. If we come back with the marker and the
        // endpoint still answers 401, the login page's "already signed in" shortcut and this page
        // would bounce between each other forever (AB#6993) — so stop and explain instead.
        if (error.status === 401) {
          if (this.loginAlreadyAttempted) {
            this.loading = false;
            this.errorMessage = this.translate.instant('DEVICE.ERROR_SESSION_REJECTED');
            return;
          }
          const tenantId = this.route.snapshot.params['tenantId'] || 'System';
          const returnUrl = `/${tenantId}/device/confirm?userCode=${encodeURIComponent(this.userCode)}`
            + `&${DeviceConfirmComponent.loginAttemptedParam}=1`;
          this.router.navigate(['/', tenantId, 'login'], {
            queryParams: { returnUrl }
          });
          return;
        }

        this.loading = false;
        this.errorMessage = error.error?.message || this.translate.instant('DEVICE.INVALID_CODE');
      }
    });
  }

  onAllow(): void {
    if (!this.context || this.submitting) return;

    this.submitting = true;
    this.errorMessage = undefined;

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
        if (result?.success === true) {
          this.success = true;
          this.context = undefined;
        } else if (result?.success === false) {
          this.showFailure(this.messageForResult(result, 'DEVICE.ERROR_AUTH_FAILED'), result.error);
        } else {
          // 2xx but not the documented { success, errorMessage, error } body: the outcome is
          // unknown (the device may or may not be approved). Never stay silent and never offer
          // a second click on a code that may already be redeemed.
          this.endWithMessage(this.translate.instant('DEVICE.ERROR_NO_CONFIRMATION'));
        }
      },
      error: (error: HttpErrorResponse) => this.onSubmitError(error)
    });
  }

  onDeny(): void {
    if (this.submitting) return;

    this.submitting = true;
    this.errorMessage = undefined;

    this.consentApi.denyDeviceAuthorization(this.userCode).subscribe({
      next: (result) => {
        this.submitting = false;
        // The server answers a deny with { success: false, error: 'access_denied' }; any other
        // error code means the code was not pending (used, expired, rejected).
        if (result?.success === false && result.error && result.error !== 'access_denied') {
          this.showFailure(this.messageForResult(result, 'DEVICE.ERROR_AUTH_FAILED'), result.error);
          return;
        }
        this.denied = true;
        this.context = undefined;
      },
      error: (error: HttpErrorResponse) => this.onSubmitError(error)
    });
  }

  private onSubmitError(error: HttpErrorResponse): void {
    this.submitting = false;
    if (error.status === 401) {
      this.endWithMessage(this.translate.instant('DEVICE.ERROR_SESSION_REJECTED'));
    } else if (error.status === 200) {
      // Body could not be parsed as JSON: same unknown outcome as a 2xx with a foreign body.
      this.endWithMessage(this.translate.instant('DEVICE.ERROR_NO_CONFIRMATION'));
    } else if (error.status === 404 || error.status === 410) {
      this.endWithMessage(this.translate.instant('DEVICE.ERROR_CODE_USED'));
    } else {
      this.errorMessage = this.translate.instant('COMMON.ERROR_GENERIC');
    }
  }

  private messageForResult(result: DeviceAuthorizationResult, fallbackKey: string): string {
    if (result.error === 'invalid_token') {
      return this.translate.instant('DEVICE.ERROR_CODE_USED');
    }
    return result.errorMessage || this.translate.instant(fallbackKey);
  }

  /** Failure the user can still act on: keep the dialog for a retry unless the code is gone. */
  private showFailure(message: string, error?: string): void {
    if (error === 'invalid_token') {
      this.endWithMessage(message);
    } else {
      this.errorMessage = message;
    }
  }

  /** Terminal failure: hide the consent dialog so the message cannot be missed. */
  private endWithMessage(message: string): void {
    this.context = undefined;
    this.errorMessage = message;
  }

  goBack(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'device']);
  }
}
