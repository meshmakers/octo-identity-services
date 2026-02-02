import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { AuthApiService } from '../../core/services/auth-api.service';
import { LogoutContext } from '../../core/models/login.models';

@Component({
  selector: 'app-logout',
  standalone: true,
  imports: [CommonModule, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header
          primaryText="OCTO"
          secondaryText="IDENTITY"
          subtitle="Sign out">
        </app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">Loading</span>
        </div>

        <ng-container *ngIf="!loading">
          <div class="logout-content">
            <p class="logout-message">
              Would you like to sign out of your session?
            </p>

            <div *ngIf="context?.clientName" class="logout-client">
              You will be signed out from <strong>{{ context!.clientName }}</strong>
            </div>

            <div class="lcars-actions">
              <button
                type="button"
                class="lcars-button-primary"
                (click)="onLogout()"
                [disabled]="submitting">
                {{ submitting ? 'Signing out...' : 'Sign Out' }}
              </button>
              <button
                type="button"
                class="lcars-button-outline"
                (click)="onCancel()"
                [disabled]="submitting">
                Cancel
              </button>
            </div>
          </div>
        </ng-container>
      </app-lcars-panel>
    </div>
  `,
  styleUrl: './logout.component.scss'
})
export class LogoutComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private authApi = inject(AuthApiService);

  loading = true;
  submitting = false;
  context?: LogoutContext;
  logoutId = '';

  ngOnInit(): void {
    this.logoutId = this.route.snapshot.queryParams['logoutId'] || '';
    this.loadContext();
  }

  private loadContext(): void {
    if (!this.logoutId) {
      this.loading = false;
      return;
    }

    this.authApi.getLogoutContext(this.logoutId).subscribe({
      next: (context) => {
        this.context = context;
        this.loading = false;

        // Auto logout if no prompt needed
        if (!context.showLogoutPrompt) {
          this.onLogout();
        }
      },
      error: () => {
        this.loading = false;
      }
    });
  }

  onLogout(): void {
    this.submitting = true;

    this.authApi.logout({ logoutId: this.logoutId }).subscribe({
      next: (result) => {
        if (result.postLogoutRedirectUri) {
          window.location.href = result.postLogoutRedirectUri;
        } else {
          // Navigate to logged-out page
          const tenantId = this.route.snapshot.params['tenantId'] || 'System';
          window.location.href = `/${tenantId}/logged-out`;
        }
      },
      error: () => {
        this.submitting = false;
      }
    });
  }

  onCancel(): void {
    window.history.back();
  }
}
