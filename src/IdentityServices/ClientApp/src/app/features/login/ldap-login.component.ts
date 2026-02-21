import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';
import { AuthApiService } from '../../core/services/auth-api.service';
import { LdapLoginRequest } from '../../core/models/login.models';

@Component({
  selector: 'app-ldap-login',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    LcarsPanelComponent,
    LcarsHeaderComponent
  ],
  templateUrl: './ldap-login.component.html',
  styleUrl: './ldap-login.component.scss'
})
export class LdapLoginComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private authApi = inject(AuthApiService);

  // Route params
  scheme = '';
  providerName = '';
  returnUrl = '';
  tenantId = 'System';

  // Form data
  username = '';
  password = '';

  // State
  submitting = false;
  errorMessage?: string;

  ngOnInit(): void {
    this.tenantId = this.route.snapshot.params['tenantId'] || 'System';
    this.scheme = this.route.snapshot.queryParams['scheme'] || '';
    this.providerName = this.route.snapshot.queryParams['name'] || this.scheme;
    this.returnUrl = this.route.snapshot.queryParams['returnUrl'] || '';

    if (!this.scheme) {
      this.errorMessage = 'Invalid authentication provider';
    }
  }

  onSubmit(): void {
    if (!this.username || !this.password) {
      this.errorMessage = 'Please enter username and password';
      return;
    }

    this.submitting = true;
    this.errorMessage = undefined;

    const request: LdapLoginRequest = {
      scheme: this.scheme,
      username: this.username,
      password: this.password,
      returnUrl: this.returnUrl
    };

    this.authApi.ldapLogin(request).subscribe({
      next: (result) => {
        this.submitting = false;
        if (result.success && result.redirectUrl) {
          window.location.href = result.redirectUrl;
        } else {
          this.errorMessage = result.errorMessage || 'Authentication failed';
        }
      },
      error: (error) => {
        this.submitting = false;
        this.errorMessage = error.error?.message || 'An error occurred during authentication';
      }
    });
  }

  onCancel(): void {
    this.router.navigate(['/', this.tenantId, 'login'], {
      queryParams: { ReturnUrl: this.returnUrl }
    });
  }
}
