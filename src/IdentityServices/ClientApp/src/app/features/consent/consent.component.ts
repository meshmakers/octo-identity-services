import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ScopeListComponent } from '../../shared/components/scope-list/scope-list.component';
import { ConsentApiService } from '../../core/services/consent-api.service';
import { ConsentContext, ScopeItem } from '../../core/models/consent.models';

@Component({
  selector: 'app-consent',
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
          [subtitle]="'CONSENT.SUBTITLE' | translate">
        </app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">{{ 'COMMON.LOADING' | translate }}</span>
        </div>

        <ng-container *ngIf="!loading && context">
          <!-- Client Info -->
          <div class="lcars-client-info">
            <div class="lcars-client-info__logo" *ngIf="context.clientLogoUrl">
              <img [src]="context.clientLogoUrl" [alt]="context.clientName" />
            </div>
            <div class="lcars-client-info__details">
              <span class="lcars-client-info__name">{{ context.clientName }}</span>
              <span class="lcars-client-info__url" *ngIf="context.clientUrl">{{ context.clientUrl }}</span>
            </div>
          </div>

          <p class="consent-description">
            {{ 'CONSENT.DESCRIPTION' | translate }}
          </p>

          <!-- Error Message -->
          <div *ngIf="errorMessage" class="lcars-error-message">
            {{ errorMessage }}
          </div>

          <!-- Identity Scopes -->
          <app-scope-list
            *ngIf="context.identityScopes.length > 0"
            [title]="'CONSENT.IDENTITY_SCOPES' | translate"
            [scopes]="context.identityScopes"
            (scopesChange)="onScopesChange($event, 'identity')">
          </app-scope-list>

          <!-- API Scopes -->
          <app-scope-list
            *ngIf="context.apiScopes.length > 0"
            [title]="'CONSENT.API_SCOPES' | translate"
            [scopes]="context.apiScopes"
            (scopesChange)="onScopesChange($event, 'api')">
          </app-scope-list>

          <!-- Remember Consent -->
          <div class="lcars-checkbox-group" *ngIf="context.allowRememberConsent">
            <input
              type="checkbox"
              id="rememberConsent"
              [(ngModel)]="rememberConsent"
              class="lcars-checkbox"
              [disabled]="submitting" />
            <label for="rememberConsent">{{ 'CONSENT.REMEMBER' | translate }}</label>
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

        <div *ngIf="!loading && !context" class="lcars-error-message">
          {{ 'CONSENT.INVALID_REQUEST' | translate }}
        </div>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './consent.component.scss'
})
export class ConsentComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private consentApi = inject(ConsentApiService);
  private translate = inject(TranslateService);

  loading = true;
  submitting = false;
  errorMessage?: string;
  context?: ConsentContext;
  rememberConsent = false;
  returnUrl = '';

  ngOnInit(): void {
    // The consent redirect historically sends the query param lowercase (`returnUrl`), unlike
    // the login redirect which sends `ReturnUrl`. Accept both casings, otherwise the consent
    // POST loses the return URL and the authorize flow dead-ends with "Invalid consent request".
    this.returnUrl = this.route.snapshot.queryParams['ReturnUrl']
                  || this.route.snapshot.queryParams['returnUrl']
                  || '';
    this.loadContext();
  }

  private loadContext(): void {
    if (!this.returnUrl) {
      this.loading = false;
      return;
    }

    this.consentApi.getConsentContext(this.returnUrl).subscribe({
      next: (context) => {
        this.context = context;
        this.loading = false;
      },
      error: () => {
        this.loading = false;
      }
    });
  }

  onScopesChange(scopes: ScopeItem[], type: 'identity' | 'api'): void {
    if (this.context) {
      if (type === 'identity') {
        this.context.identityScopes = scopes;
      } else {
        this.context.apiScopes = scopes;
      }
    }
  }

  onAllow(): void {
    if (!this.context) return;

    this.submitting = true;
    this.errorMessage = undefined;

    const scopesConsented = [
      ...this.context.identityScopes.filter(s => s.checked).map(s => s.name),
      ...this.context.apiScopes.filter(s => s.checked).map(s => s.name)
    ];

    this.consentApi.grantConsent({
      returnUrl: this.returnUrl,
      scopesConsented,
      rememberConsent: this.rememberConsent
    }).subscribe({
      next: (result) => {
        if (result.success && result.redirectUrl) {
          window.location.href = result.redirectUrl;
        } else {
          this.submitting = false;
          this.errorMessage = result.errorMessage || result.validationError || this.translate.instant('CONSENT.ERROR_PROCESS');
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.message || this.translate.instant('COMMON.ERROR_GENERIC');
      }
    });
  }

  onDeny(): void {
    this.submitting = true;

    this.consentApi.denyConsent(this.returnUrl).subscribe({
      next: (result) => {
        if (result.redirectUrl) {
          window.location.href = result.redirectUrl;
        }
      },
      error: () => {
        this.submitting = false;
      }
    });
  }
}
