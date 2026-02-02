import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { ManageApiService } from '../../core/services/manage-api.service';
import { UserProfile } from '../../core/models/manage.models';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule, RouterLink, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header
          primaryText="OCTO"
          secondaryText="IDENTITY"
          subtitle="Your Profile">
        </app-lcars-header>

        <div *ngIf="loading" class="lcars-loading">
          <div class="lcars-loading__spinner"></div>
          <span class="lcars-loading__text">Loading</span>
        </div>

        <ng-container *ngIf="!loading && profile">
          <div class="profile-section">
            <h3 class="section-title">Account Information</h3>

            <div class="profile-item">
              <span class="profile-item__label">Username</span>
              <span class="profile-item__value">{{ profile.userName }}</span>
            </div>

            <div class="profile-item" *ngIf="profile.email">
              <span class="profile-item__label">Email</span>
              <span class="profile-item__value">
                {{ profile.email }}
                <span class="status-badge" [class.status-badge--success]="profile.emailConfirmed" [class.status-badge--warning]="!profile.emailConfirmed">
                  {{ profile.emailConfirmed ? 'Verified' : 'Not Verified' }}
                </span>
              </span>
            </div>

            <div class="profile-item" *ngIf="profile.phoneNumber">
              <span class="profile-item__label">Phone</span>
              <span class="profile-item__value">
                {{ profile.phoneNumber }}
                <span class="status-badge" [class.status-badge--success]="profile.phoneNumberConfirmed">
                  {{ profile.phoneNumberConfirmed ? 'Verified' : 'Not Verified' }}
                </span>
              </span>
            </div>
          </div>

          <div class="profile-section">
            <h3 class="section-title">Security</h3>

            <div class="profile-item">
              <span class="profile-item__label">Password</span>
              <span class="profile-item__value">
                <span class="status-badge status-badge--info">
                  {{ profile.hasPassword ? 'Set' : 'Not Set' }}
                </span>
                <a [routerLink]="profile.hasPassword ? ['password'] : ['set-password']" class="action-link">
                  {{ profile.hasPassword ? 'Change' : 'Set Password' }}
                </a>
              </span>
            </div>

            <div class="profile-item">
              <span class="profile-item__label">Two-Factor Auth</span>
              <span class="profile-item__value">
                <span class="status-badge" [class.status-badge--success]="profile.twoFactorEnabled" [class.status-badge--warning]="!profile.twoFactorEnabled">
                  {{ profile.twoFactorEnabled ? 'Enabled' : 'Disabled' }}
                </span>
              </span>
            </div>

            <div class="profile-item">
              <span class="profile-item__label">External Logins</span>
              <span class="profile-item__value">
                {{ profile.externalLogins.length }} connected
                <a routerLink="logins" class="action-link">Manage</a>
              </span>
            </div>

            <div class="profile-item">
              <span class="profile-item__label">App Permissions</span>
              <span class="profile-item__value">
                <a routerLink="../grants" class="action-link">View Granted Apps</a>
              </span>
            </div>
          </div>
        </ng-container>

        <div *ngIf="!loading && !profile" class="lcars-error-message">
          Failed to load profile. Please try again.
        </div>
      </app-lcars-panel>
    </div>
  `,
  styleUrl: './profile.component.scss'
})
export class ProfileComponent implements OnInit {
  private manageApi = inject(ManageApiService);

  loading = true;
  profile?: UserProfile;

  ngOnInit(): void {
    this.loadProfile();
  }

  private loadProfile(): void {
    this.manageApi.getProfile().subscribe({
      next: (profile) => {
        this.profile = profile;
        this.loading = false;
      },
      error: () => {
        this.loading = false;
      }
    });
  }
}
