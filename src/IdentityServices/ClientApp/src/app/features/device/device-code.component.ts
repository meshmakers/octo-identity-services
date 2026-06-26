import { Component, inject, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';

@Component({
  selector: 'app-device-code',
  standalone: true,
  imports: [CommonModule, FormsModule, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel>
        <app-lcars-header
          subtitle="Device Authorization"
          [showUserMenu]="false">
        </app-lcars-header>

        <div class="device-content">
          <p class="device-description">
            Enter the code displayed on your device to authorize access.
          </p>

          <form (ngSubmit)="onSubmit()">
            <div class="lcars-form-group">
              <label for="userCode">Device Code</label>
              <input
                type="text"
                id="userCode"
                name="userCode"
                [(ngModel)]="userCode"
                required
                autocomplete="off"
                placeholder="123456789"
                class="user-code-input"
                [disabled]="submitting" />
            </div>

            <div *ngIf="errorMessage" class="lcars-error-message">
              {{ errorMessage }}
            </div>

            <div class="lcars-actions">
              <button
                type="submit"
                class="lcars-button-primary"
                [disabled]="submitting || !userCode">
                {{ submitting ? 'Verifying...' : 'Continue' }}
              </button>
            </div>
          </form>
        </div>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './device-code.component.scss'
})
export class DeviceCodeComponent implements OnInit {
  private router = inject(Router);
  private route = inject(ActivatedRoute);

  userCode = '';
  submitting = false;
  errorMessage?: string;

  ngOnInit(): void {
    // Check if userCode is provided in URL query params
    const userCodeFromUrl = this.route.snapshot.queryParams['userCode'];
    if (userCodeFromUrl) {
      this.userCode = userCodeFromUrl.toUpperCase();
      // Auto-navigate to confirmation page
      this.onSubmit();
    }
  }

  onSubmit(): void {
    if (!this.userCode) return;

    this.submitting = true;
    this.errorMessage = undefined;

    const tenantId = this.route.snapshot.params['tenantId'] || 'System';

    // Navigate to confirmation page with user code
    this.router.navigate(['/', tenantId, 'device', 'confirm'], {
      queryParams: { userCode: this.userCode.toUpperCase() }
    });
  }
}
