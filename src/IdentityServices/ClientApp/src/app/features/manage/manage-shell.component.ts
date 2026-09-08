import { Component, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet, RouterLink, RouterLinkActive, ActivatedRoute } from '@angular/router';
import { TranslatePipe } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { getTenantIdFromUrl } from '../../core/utils/tenant.utils';

/**
 * Shell for the "/{tenant}/manage" account area (AB#5135). Renders the shared LCARS panel +
 * header once, then a lightweight LCARS tab strip and a router-outlet for the active tab.
 * The three tabs are child routes so they are deep-linkable and browser back/forward works:
 *   ''          -> Profil (read-only account info)
 *   'security'  -> Sicherheit (password / 2FA / external logins / grants)
 *   'identities'-> Meine Identitäten (self-service verified identifiers)
 * The security ACTION pages (password, logins, 2fa*) remain their own full-panel routes
 * outside this shell, so their existing deep-links and "Back to Profile" flows are untouched.
 */
@Component({
  selector: 'app-manage-shell',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive, TranslatePipe, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header [subtitle]="'MANAGE.SUBTITLE' | translate"></app-lcars-header>

        <nav class="lcars-tabs" role="tablist">
          <a
            class="lcars-tab"
            role="tab"
            [routerLink]="['/', tenantId, 'manage']"
            routerLinkActive="lcars-tab--active"
            [routerLinkActiveOptions]="{ exact: true }">
            {{ 'MANAGE.TAB_PROFILE' | translate }}
          </a>
          <a
            class="lcars-tab"
            role="tab"
            [routerLink]="['/', tenantId, 'manage', 'security']"
            routerLinkActive="lcars-tab--active">
            {{ 'MANAGE.TAB_SECURITY' | translate }}
          </a>
          <a
            class="lcars-tab"
            role="tab"
            [routerLink]="['/', tenantId, 'manage', 'identities']"
            routerLinkActive="lcars-tab--active">
            {{ 'MANAGE.TAB_IDENTITIES' | translate }}
          </a>
        </nav>

        <div class="lcars-tab-content">
          <router-outlet></router-outlet>
        </div>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './manage-shell.component.scss'
})
export class ManageShellComponent {
  private route = inject(ActivatedRoute);

  protected readonly tenantId = this.route.snapshot.params['tenantId'] || getTenantIdFromUrl();
}
