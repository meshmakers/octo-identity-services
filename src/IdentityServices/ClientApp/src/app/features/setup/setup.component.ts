import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { SetupApiService } from '../../core/services/setup-api.service';

@Component({
  selector: 'app-setup',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    RouterLink,
    TranslatePipe,
    LcarsPanelComponent,
    LcarsHeaderComponent
  ],
  templateUrl: './setup.component.html',
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './setup.component.scss'
})
export class SetupComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private setupApi = inject(SetupApiService);
  private translate = inject(TranslateService);

  // State
  loading = true;
  submitting = false;
  success = false;
  errorMessage?: string;

  // Form data
  email = '';
  password = '';
  confirmPassword = '';

  // Computed
  tenantId = 'System';

  get passwordMismatch(): boolean {
    return this.confirmPassword.length > 0 && this.password !== this.confirmPassword;
  }

  ngOnInit(): void {
    this.tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.checkSetupStatus();
  }

  private checkSetupStatus(): void {
    this.setupApi.getSetupStatus().subscribe({
      next: () => {
        // Setup is required — show the form
        this.loading = false;
      },
      error: (error) => {
        if (error?.status === 404) {
          // 404 means users already exist — redirect to login
          this.router.navigate(['/', this.tenantId, 'login']);
        } else {
          this.loading = false;
          this.errorMessage = error?.error?.errorMessage || this.translate.instant('SETUP.ERROR_STATUS');
        }
      }
    });
  }

  onSubmit(): void {
    if (!this.email || !this.password || !this.confirmPassword) {
      this.errorMessage = this.translate.instant('SETUP.ERROR_FILL_ALL');
      return;
    }

    if (this.password !== this.confirmPassword) {
      this.errorMessage = this.translate.instant('COMMON.PASSWORDS_MISMATCH');
      return;
    }

    this.submitting = true;
    this.errorMessage = undefined;

    this.setupApi.createAdminUser({
      email: this.email,
      password: this.password,
      confirmPassword: this.confirmPassword
    }).subscribe({
      next: (result) => {
        this.submitting = false;
        if (result.success) {
          this.success = true;
        } else {
          this.errorMessage = result.errorMessage || this.translate.instant('SETUP.ERROR_CREATE');
        }
      },
      error: (error) => {
        this.submitting = false;
        if (error.status === 404) {
          // Users were created by someone else — redirect to login
          this.router.navigate(['/', this.tenantId, 'login']);
        } else {
          this.errorMessage = error.error?.errorMessage || this.translate.instant('FORGOT_PASSWORD.ERROR_GENERIC');
        }
      }
    });
  }
}
