import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, ActivatedRoute } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { GrantsApiService } from '../../core/services/grants-api.service';
import { GrantInfo } from '../../core/models/grants.models';

@Component({
  selector: 'app-grants',
  standalone: true,
  imports: [CommonModule, TranslatePipe, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header
          [subtitle]="'GRANTS.SUBTITLE' | translate">
        </app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">{{ 'COMMON.LOADING' | translate }}</span>
        </div>

        <ng-container *ngIf="!loading">
          <div *ngIf="successMessage" class="lcars-success-message">
            {{ successMessage }}
          </div>

          <div *ngIf="errorMessage" class="lcars-error-message">
            {{ errorMessage }}
          </div>

          <p class="description" *ngIf="grants.length > 0">
            {{ 'GRANTS.DESCRIPTION' | translate }}
          </p>

          <div *ngIf="grants.length === 0" class="empty-state">
            <div class="empty-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
              </svg>
            </div>
            <p>{{ 'GRANTS.EMPTY' | translate }}</p>
          </div>

          <div class="grants-grid">
          <div *ngFor="let grant of grants" class="grant-card">
            <div class="grant-card__header">
              <div class="grant-card__logo" *ngIf="grant.clientLogoUrl">
                <img [src]="grant.clientLogoUrl" [alt]="grant.clientName" />
              </div>
              <div class="grant-card__info">
                <span class="grant-card__name">{{ grant.clientName || grant.clientId }}</span>
                <span class="grant-card__url" *ngIf="grant.clientUrl">{{ grant.clientUrl }}</span>
              </div>
            </div>

            <div class="grant-card__scopes">
              <div class="scope-group" *ngIf="grant.identityGrantNames.length > 0">
                <span class="scope-group__label">{{ 'GRANTS.PERSONAL_INFORMATION' | translate }}</span>
                <div class="scope-group__items">
                  <span *ngFor="let scope of grant.identityGrantNames" class="scope-tag">
                    {{ scope }}
                  </span>
                </div>
              </div>

              <div class="scope-group" *ngIf="grant.apiGrantNames.length > 0">
                <span class="scope-group__label">{{ 'GRANTS.API_ACCESS' | translate }}</span>
                <div class="scope-group__items">
                  <span *ngFor="let scope of grant.apiGrantNames" class="scope-tag scope-tag--api">
                    {{ scope }}
                  </span>
                </div>
              </div>
            </div>

            <div class="grant-card__meta">
              <span>{{ 'GRANTS.GRANTED' | translate }} {{ grant.created | date:'medium' }}</span>
              <span *ngIf="grant.expires">{{ 'GRANTS.EXPIRES' | translate }} {{ grant.expires | date:'medium' }}</span>
            </div>

            <div class="grant-card__actions">
              <button
                type="button"
                class="lcars-button-error"
                (click)="revokeGrant(grant)"
                [disabled]="revokingGrant === grant.clientId">
                {{ (revokingGrant === grant.clientId ? 'GRANTS.REVOKING' : 'GRANTS.REVOKE') | translate }}
              </button>
            </div>
          </div>
          </div>

          <div class="lcars-actions">
            <button type="button" class="lcars-button-outline" (click)="goBack()">
              {{ 'COMMON.BACK_TO_PROFILE' | translate }}
            </button>
          </div>
        </ng-container>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './grants.component.scss'
})
export class GrantsComponent implements OnInit {
  private grantsApi = inject(GrantsApiService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  private translate = inject(TranslateService);

  loading = true;
  grants: GrantInfo[] = [];
  successMessage?: string;
  errorMessage?: string;
  revokingGrant?: string;

  ngOnInit(): void {
    this.loadGrants();
  }

  private loadGrants(): void {
    this.grantsApi.getGrants().subscribe({
      next: (grants) => {
        this.grants = grants;
        this.loading = false;
      },
      error: () => {
        this.loading = false;
        this.errorMessage = this.translate.instant('GRANTS.ERROR_LOAD');
      }
    });
  }

  revokeGrant(grant: GrantInfo): void {
    this.revokingGrant = grant.clientId;
    this.errorMessage = undefined;
    this.successMessage = undefined;

    this.grantsApi.revokeGrant({ clientId: grant.clientId }).subscribe({
      next: (result) => {
        this.revokingGrant = undefined;
        if (result.success) {
          this.successMessage = this.translate.instant('GRANTS.REVOKED', { app: grant.clientName || grant.clientId });
          this.grants = this.grants.filter(g => g.clientId !== grant.clientId);
        } else {
          this.errorMessage = result.errorMessage || this.translate.instant('GRANTS.ERROR_REVOKE');
        }
      },
      error: () => {
        this.revokingGrant = undefined;
        this.errorMessage = this.translate.instant('COMMON.ERROR_GENERIC');
      }
    });
  }

  goBack(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'manage']);
  }
}
