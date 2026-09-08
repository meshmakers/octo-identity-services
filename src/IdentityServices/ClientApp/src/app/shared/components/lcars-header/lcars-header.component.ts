import { Component, Input, inject, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, ActivatedRoute } from '@angular/router';
import { TranslatePipe } from '@ngx-translate/core';
import { OemService } from '../../../core/services/oem.service';
import { AuthStateService } from '../../../core/services/auth-state.service';
import { AuthApiService } from '../../../core/services/auth-api.service';
import { AppLanguage, LanguageService } from '../../../core/services/language.service';
import { getTenantIdFromUrl } from '../../../core/utils/tenant.utils';

@Component({
  selector: 'app-lcars-header',
  standalone: true,
  imports: [CommonModule, TranslatePipe],
  template: `
    <header class="lcars-header">
      <!-- Language switcher in top right (AB#5137): persisted user override over browser default -->
      <div class="lcars-header__lang" role="group" [attr.aria-label]="'HEADER.LANGUAGE' | translate">
        <button
          *ngFor="let lang of languages"
          type="button"
          class="lang-button"
          [class.lang-button--active]="languageService.currentLanguage() === lang"
          (click)="onSelectLanguage(lang)">
          {{ lang.toUpperCase() }}
        </button>
      </div>

      <!-- User menu in top right -->
      <div class="lcars-header__user-menu" *ngIf="showUserMenu && (authState.authState$ | async) as state">
        <ng-container *ngIf="!state.loading">
          <div class="user-indicator" *ngIf="state.isAuthenticated && state.user">
            <span class="user-indicator__name">{{ state.user.userName }}</span>
            <button class="user-indicator__logout" (click)="onLogout()">
              {{ 'HEADER.LOGOUT' | translate }}
            </button>
          </div>
        </ng-container>
      </div>

      <div class="lcars-header__logo" *ngIf="showLogo && (oemService.config | async)?.logoUrl as logoUrl">
        <img [src]="logoUrl" [alt]="(oemService.config | async)?.appName || 'Logo'" />
      </div>
      <div class="lcars-header__title">
        <span class="title-prefix">{{ primaryText }}</span>
        <span class="title-main">{{ secondaryText }}</span>
        <span class="title-suffix" *ngIf="suffixText">{{ suffixText }}</span>
      </div>
      <p class="lcars-header__subtitle" *ngIf="subtitle">{{ subtitle }}</p>
    </header>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './lcars-header.component.scss'
})
export class LcarsHeaderComponent implements OnInit {
  @Input() primaryText = 'OCTO';
  @Input() secondaryText = 'MESH';
  @Input() suffixText = 'Identity';
  @Input() subtitle?: string;
  @Input() showLogo = true;
  @Input() showUserMenu = true;

  protected oemService = inject(OemService);
  protected authState = inject(AuthStateService);
  protected languageService = inject(LanguageService);
  private authApi = inject(AuthApiService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);

  protected readonly languages = LanguageService.supportedLanguages;

  onSelectLanguage(language: AppLanguage): void {
    void this.languageService.setLanguage(language);
  }

  ngOnInit(): void {
    // Check auth status when component initializes
    if (this.showUserMenu) {
      this.authState.checkAuthStatus().subscribe();
    }
  }

  onLogout(): void {
    const tenantId = getTenantIdFromUrl();

    this.authApi.logout({ logoutId: '' }).subscribe({
      next: () => {
        this.authState.clearAuthState();
        this.router.navigate([`/${tenantId}/login`]);
      },
      error: () => {
        // Even on error, clear state and redirect
        this.authState.clearAuthState();
        this.router.navigate([`/${tenantId}/login`]);
      }
    });
  }
}
