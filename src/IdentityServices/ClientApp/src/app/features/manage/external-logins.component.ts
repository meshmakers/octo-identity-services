import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, ActivatedRoute } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ExternalProviderButtonComponent } from '../../shared/components/external-provider-button/external-provider-button.component';
import { ManageApiService } from '../../core/services/manage-api.service';
import { ExternalLoginInfo } from '../../core/models/manage.models';
import { ExternalProvider } from '../../core/models/login.models';

@Component({
  selector: 'app-external-logins',
  standalone: true,
  imports: [
    CommonModule,
    LcarsPanelComponent,
    LcarsHeaderComponent,
    ExternalProviderButtonComponent
  ],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header
          subtitle="External Logins">
        </app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">Loading</span>
        </div>

        <ng-container *ngIf="!loading">
          <div *ngIf="successMessage" class="lcars-success-message">
            {{ successMessage }}
          </div>

          <div *ngIf="errorMessage" class="lcars-error-message">
            {{ errorMessage }}
          </div>

          <!-- Connected Logins -->
          <div class="logins-section">
            <h3 class="section-title">Connected Accounts</h3>

            <div *ngIf="logins.length === 0" class="empty-state">
              No external accounts connected.
            </div>

            <div *ngFor="let login of logins" class="login-item">
              <div class="login-item__info">
                <span class="login-item__provider">{{ login.providerDisplayName }}</span>
                <span class="login-item__key">{{ login.providerKey | slice:0:20 }}...</span>
              </div>
              <button
                type="button"
                class="lcars-button-flat-error"
                (click)="removeLogin(login)"
                [disabled]="removingLogin === login.providerKey">
                {{ removingLogin === login.providerKey ? 'Removing...' : 'Remove' }}
              </button>
            </div>
          </div>

          <!-- Available Providers -->
          <div class="logins-section" *ngIf="availableProviders.length > 0">
            <h3 class="section-title">Add External Login</h3>

            <div class="providers-grid">
              <app-external-provider-button
                *ngFor="let provider of availableProviders"
                [provider]="provider"
                (login)="addLogin($event)">
              </app-external-provider-button>
            </div>
          </div>

          <div class="lcars-actions">
            <button type="button" class="lcars-button-outline" (click)="goBack()">
              Back to Profile
            </button>
          </div>
        </ng-container>
      </app-lcars-panel>
    </div>
  `,
  styleUrl: './external-logins.component.scss'
})
export class ExternalLoginsComponent implements OnInit {
  private manageApi = inject(ManageApiService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);

  loading = true;
  logins: ExternalLoginInfo[] = [];
  availableProviders: ExternalProvider[] = [];
  successMessage?: string;
  errorMessage?: string;
  removingLogin?: string;

  ngOnInit(): void {
    this.loadData();
  }

  private loadData(): void {
    this.loading = true;

    // Load both logins and available providers
    this.manageApi.getExternalLogins().subscribe({
      next: (logins) => {
        this.logins = logins;
        this.loadAvailableProviders();
      },
      error: () => {
        this.loading = false;
        this.errorMessage = 'Failed to load external logins';
      }
    });
  }

  private loadAvailableProviders(): void {
    this.manageApi.getAvailableProviders().subscribe({
      next: (providers) => {
        // Filter out already connected providers
        const connectedSchemes = this.logins.map(l => l.loginProvider.toLowerCase());
        this.availableProviders = providers.filter(
          p => !connectedSchemes.includes(p.scheme.toLowerCase())
        );
        this.loading = false;
      },
      error: () => {
        this.loading = false;
      }
    });
  }

  addLogin(provider: ExternalProvider): void {
    this.manageApi.addExternalLogin(provider.scheme);
  }

  removeLogin(login: ExternalLoginInfo): void {
    this.removingLogin = login.providerKey;
    this.errorMessage = undefined;
    this.successMessage = undefined;

    this.manageApi.removeExternalLogin({
      loginProvider: login.loginProvider,
      providerKey: login.providerKey
    }).subscribe({
      next: (result) => {
        this.removingLogin = undefined;
        if (result.success) {
          this.successMessage = `${login.providerDisplayName} account removed`;
          this.logins = this.logins.filter(l => l.providerKey !== login.providerKey);
          this.loadAvailableProviders();
        } else {
          this.errorMessage = result.errorMessage || 'Failed to remove login';
        }
      },
      error: () => {
        this.removingLogin = undefined;
        this.errorMessage = 'An error occurred';
      }
    });
  }

  goBack(): void {
    const tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.router.navigate(['/', tenantId, 'manage']);
  }
}
