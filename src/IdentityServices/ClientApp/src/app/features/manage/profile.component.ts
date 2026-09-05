import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ManageApiService } from '../../core/services/manage-api.service';
import { UserProfile } from '../../core/models/manage.models';

/**
 * "Profil" tab of the manage area (AB#5135): read-only account information. Rendered inside
 * {@link ManageShellComponent}'s panel via router-outlet, so it emits INNER content only
 * (no own container/panel/header). The security actions moved to the "Sicherheit" tab
 * ({@link SecurityComponent}).
 */
@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div *ngIf="loading" class="lcars-loading">
      <div class="lcars-loading__spinner"></div>
      <span class="lcars-loading__text">Loading</span>
    </div>

    <ng-container *ngIf="!loading && profile">
      <div class="profile-section">
        <h3 class="section-title">Account Information</h3>

        <div class="profile-item">
          <span class="profile-item__label">Tenant</span>
          <span class="profile-item__value">{{ profile.tenantId }}</span>
        </div>

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
        <h3 class="section-title">Roles</h3>
        <div *ngIf="profile.roles.length" class="role-badges">
          <span *ngFor="let role of profile.roles" class="status-badge status-badge--info">{{ role }}</span>
        </div>
        <div *ngIf="!profile.roles.length" class="profile-item">
          <span class="profile-item__value">No roles assigned</span>
        </div>
      </div>

      <div class="profile-section">
        <h3 class="section-title">Groups</h3>
        <div *ngIf="profile.groups.length" class="role-badges">
          <span *ngFor="let group of profile.groups" class="status-badge status-badge--info">{{ group }}</span>
        </div>
        <div *ngIf="!profile.groups.length" class="profile-item">
          <span class="profile-item__value">No group memberships</span>
        </div>
      </div>

      <div class="profile-section">
        <h3 class="section-title">Allowed Tenants</h3>
        <div *ngIf="profile.allowedTenants.length" class="role-badges">
          <span *ngFor="let tenant of profile.allowedTenants" class="status-badge status-badge--info">{{ tenant }}</span>
        </div>
        <div *ngIf="!profile.allowedTenants.length" class="profile-item">
          <span class="profile-item__value">No additional tenants</span>
        </div>
      </div>
    </ng-container>

    <div *ngIf="!loading && !profile" class="lcars-error-message">
      Failed to load profile. Please try again.
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
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
