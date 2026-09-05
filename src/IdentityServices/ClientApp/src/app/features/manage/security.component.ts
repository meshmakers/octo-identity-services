import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink, ActivatedRoute } from '@angular/router';
import { ManageApiService } from '../../core/services/manage-api.service';
import { UserProfile } from '../../core/models/manage.models';
import { getTenantIdFromUrl } from '../../core/utils/tenant.utils';

/**
 * "Sicherheit" tab of the manage area (AB#5135): the security actions previously living at the
 * bottom of the profile page — password, two-factor, external logins, granted apps. Rendered
 * inside {@link ManageShellComponent} (inner content only). Each row links out to its existing
 * full-panel action route (manage/password, manage/2fa, manage/logins, grants), so those
 * deep-links and their own "Back to Profile" flows keep working unchanged.
 */
@Component({
  selector: 'app-security',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div *ngIf="loading" class="lcars-loading">
      <div class="lcars-loading__spinner"></div>
      <span class="lcars-loading__text">Loading</span>
    </div>

    <ng-container *ngIf="!loading && profile">
      <div class="profile-section">
        <h3 class="section-title">Security</h3>

        <div class="profile-item">
          <span class="profile-item__label">Password</span>
          <span class="profile-item__value">
            <span class="status-badge status-badge--info">
              {{ profile.hasPassword ? 'Set' : 'Not Set' }}
            </span>
            <a [routerLink]="passwordLink" class="action-link">
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
            <a [routerLink]="['/', tenantId, 'manage', '2fa']" class="action-link">Manage</a>
          </span>
        </div>

        <div class="profile-item">
          <span class="profile-item__label">External Logins</span>
          <span class="profile-item__value">
            {{ profile.externalLogins.length }} connected
            <a [routerLink]="['/', tenantId, 'manage', 'logins']" class="action-link">Manage</a>
          </span>
        </div>

        <div class="profile-item">
          <span class="profile-item__label">App Permissions</span>
          <span class="profile-item__value">
            <a [routerLink]="['/', tenantId, 'grants']" class="action-link">View Granted Apps</a>
          </span>
        </div>
      </div>
    </ng-container>

    <div *ngIf="!loading && !profile" class="lcars-error-message">
      Failed to load security settings. Please try again.
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './profile.component.scss'
})
export class SecurityComponent implements OnInit {
  private manageApi = inject(ManageApiService);
  private route = inject(ActivatedRoute);

  protected readonly tenantId = this.route.snapshot.params['tenantId'] || getTenantIdFromUrl();

  loading = true;
  profile?: UserProfile;

  get passwordLink(): (string | undefined)[] {
    return ['/', this.tenantId, 'manage', this.profile?.hasPassword ? 'password' : 'set-password'];
  }

  ngOnInit(): void {
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
