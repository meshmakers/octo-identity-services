import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
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
    LcarsPanelComponent,
    LcarsHeaderComponent
  ],
  templateUrl: './setup.component.html',
  styleUrl: './setup.component.scss'
})
export class SetupComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private setupApi = inject(SetupApiService);

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
          this.errorMessage = error?.error?.errorMessage || 'Unable to check setup status. Please try again.';
        }
      }
    });
  }

  onSubmit(): void {
    if (!this.email || !this.password || !this.confirmPassword) {
      this.errorMessage = 'Please fill in all fields';
      return;
    }

    if (this.password !== this.confirmPassword) {
      this.errorMessage = 'Passwords do not match';
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
          this.errorMessage = result.errorMessage || 'Failed to create admin user';
        }
      },
      error: (error) => {
        this.submitting = false;
        if (error.status === 404) {
          // Users were created by someone else — redirect to login
          this.router.navigate(['/', this.tenantId, 'login']);
        } else {
          this.errorMessage = error.error?.errorMessage || 'An error occurred. Please try again.';
        }
      }
    });
  }
}
