import { Routes } from '@angular/router';

export const routes: Routes = [
  // Legacy route: /Manage redirects to /System/manage (for backwards compatibility)
  {
    path: 'Manage',
    redirectTo: 'System/manage',
    pathMatch: 'full'
  },
  {
    path: ':tenantId',
    children: [
      {
        path: 'login',
        loadComponent: () => import('./features/login/login.component')
          .then(m => m.LoginComponent)
      },
      {
        path: '2fa-login',
        loadComponent: () => import('./features/login/two-factor-login.component')
          .then(m => m.TwoFactorLoginComponent)
      },
      {
        path: 'ldap-login',
        loadComponent: () => import('./features/login/ldap-login.component')
          .then(m => m.LdapLoginComponent)
      },
      {
        path: 'forgot-password',
        loadComponent: () => import('./features/login/forgot-password.component')
          .then(m => m.ForgotPasswordComponent)
      },
      {
        path: 'reset-password',
        loadComponent: () => import('./features/login/reset-password.component')
          .then(m => m.ResetPasswordComponent)
      },
      {
        path: 'logout',
        loadComponent: () => import('./features/logout/logout.component')
          .then(m => m.LogoutComponent)
      },
      {
        path: 'logged-out',
        loadComponent: () => import('./features/logout/logged-out.component')
          .then(m => m.LoggedOutComponent)
      },
      {
        path: 'logout/callback',
        loadComponent: () => import('./features/logout-callback/logout-callback.component')
          .then(m => m.LogoutCallbackComponent)
      },
      {
        path: 'consent',
        loadComponent: () => import('./features/consent/consent.component')
          .then(m => m.ConsentComponent)
      },
      {
        path: 'device',
        loadComponent: () => import('./features/device/device-code.component')
          .then(m => m.DeviceCodeComponent)
      },
      {
        path: 'device/confirm',
        loadComponent: () => import('./features/device/device-confirm.component')
          .then(m => m.DeviceConfirmComponent)
      },
      {
        path: 'error',
        loadComponent: () => import('./features/error/error.component')
          .then(m => m.ErrorComponent)
      },
      {
        path: 'manage',
        children: [
          {
            path: '',
            loadComponent: () => import('./features/manage/profile.component')
              .then(m => m.ProfileComponent)
          },
          {
            path: 'password',
            loadComponent: () => import('./features/manage/change-password.component')
              .then(m => m.ChangePasswordComponent)
          },
          {
            path: 'logins',
            loadComponent: () => import('./features/manage/external-logins.component')
              .then(m => m.ExternalLoginsComponent)
          },
          {
            path: '2fa',
            loadComponent: () => import('./features/manage/two-factor/two-factor-status.component')
              .then(m => m.TwoFactorStatusComponent)
          },
          {
            path: '2fa/setup',
            loadComponent: () => import('./features/manage/two-factor/authenticator-setup.component')
              .then(m => m.AuthenticatorSetupComponent)
          },
          {
            path: '2fa/recovery-codes',
            loadComponent: () => import('./features/manage/two-factor/recovery-codes.component')
              .then(m => m.RecoveryCodesComponent)
          }
        ]
      },
      {
        path: 'grants',
        loadComponent: () => import('./features/grants/grants.component')
          .then(m => m.GrantsComponent)
      },
      {
        path: '',
        redirectTo: 'login',
        pathMatch: 'full'
      }
    ]
  },
  {
    path: '',
    redirectTo: 'System/login',
    pathMatch: 'full'
  },
  {
    path: '**',
    redirectTo: 'System/login'
  }
];
