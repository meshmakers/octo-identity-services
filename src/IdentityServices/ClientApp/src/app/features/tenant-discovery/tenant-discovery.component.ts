import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';

interface TenantDiscoveryResult {
  found: boolean;
  tenants: { tenantId: string }[];
  message?: string;
}

@Component({
  selector: 'app-tenant-discovery',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    LcarsPanelComponent,
    LcarsHeaderComponent
  ],
  templateUrl: './tenant-discovery.component.html',
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './tenant-discovery.component.scss'
})
export class TenantDiscoveryComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private http = inject(HttpClient);

  // State
  step: 'input' | 'select' | 'error' = 'input';
  loading = false;
  errorMessage?: string;

  // Form data
  emailOrUsername = '';
  selectedTenant = '';

  // Results
  discoveredTenants: string[] = [];

  // OAuth return URL (the original /connect/authorize URL)
  private returnUrl = '';

  ngOnInit(): void {
    this.returnUrl = this.route.snapshot.queryParams['returnUrl'] || '';

    // knownTenants from session cookies are unreliable — they reflect browser
    // sessions from any previous user, not the current user's memberships.
    // Always require email/username input to verify tenant access via the
    // lookup endpoint. This prevents showing tenants the user doesn't belong to.
  }

  onLookup(): void {
    if (!this.emailOrUsername.trim() || !this.returnUrl) {
      return;
    }

    this.loading = true;
    this.errorMessage = undefined;

    // POST directly to /api/tenant-discovery/lookup (no tenant prefix)
    this.http.post<TenantDiscoveryResult>('/api/tenant-discovery/lookup', {
      emailOrUsername: this.emailOrUsername.trim()
    }).subscribe({
      next: (result) => {
        this.loading = false;

        if (!result.found || result.tenants.length === 0) {
          this.step = 'error';
          this.errorMessage = result.message || 'Unable to determine your organization. Please contact your administrator.';
          return;
        }

        if (result.tenants.length === 1) {
          // Single tenant — redirect immediately
          this.redirectWithTenant(result.tenants[0].tenantId);
          return;
        }

        // Multiple tenants — show selection
        this.discoveredTenants = result.tenants.map(t => t.tenantId);
        this.selectedTenant = this.discoveredTenants[0];
        this.step = 'select';
      },
      error: (err) => {
        this.loading = false;
        if (err.status === 429) {
          this.step = 'error';
          this.errorMessage = 'Too many attempts. Please wait a moment and try again.';
        } else {
          this.step = 'error';
          this.errorMessage = 'An error occurred. Please try again later.';
        }
      }
    });
  }

  onSelectTenant(): void {
    if (this.selectedTenant) {
      this.redirectWithTenant(this.selectedTenant);
    }
  }

  onBack(): void {
    this.step = 'input';
    this.errorMessage = undefined;
    this.discoveredTenants = [];
  }

  private redirectWithTenant(tenantId: string): void {
    // Append acr_values=tenant:{tenantId} to the original authorize URL
    try {
      const url = new URL(this.returnUrl, window.location.origin);
      const existingAcr = url.searchParams.get('acr_values') || '';
      const tenantAcr = `tenant:${tenantId}`;
      const newAcr = existingAcr ? `${existingAcr} ${tenantAcr}` : tenantAcr;
      url.searchParams.set('acr_values', newAcr);
      window.location.href = url.toString();
    } catch {
      // Fallback: simple string concatenation
      const separator = this.returnUrl.includes('?') ? '&' : '?';
      window.location.href = `${this.returnUrl}${separator}acr_values=${encodeURIComponent(`tenant:${tenantId}`)}`;
    }
  }
}
