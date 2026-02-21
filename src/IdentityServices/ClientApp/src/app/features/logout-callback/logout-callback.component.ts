import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';

/**
 * Front-Channel Logout Callback Component
 *
 * This component is loaded in an iframe by the Identity Server during Single Logout (SLO).
 * It clears all local authentication state and tokens.
 */
@Component({
  selector: 'app-logout-callback',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="logout-callback">
      <div class="logout-callback__message">{{ message }}</div>
    </div>
  `,
  styles: [`
    .logout-callback {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100px;
      font-family: var(--lcars-font-primary, 'Montserrat', sans-serif);
      color: #64ceb9;
      font-size: 14px;
    }
  `]
})
export class LogoutCallbackComponent implements OnInit {
  message = 'Processing logout...';

  ngOnInit(): void {
    this.performLogout();
  }

  private performLogout(): void {
    try {
      // Clear all authentication-related data from storage
      this.clearStorage();

      // Clear cookies if accessible
      this.clearCookies();

      this.message = 'Logged out successfully';

      // Notify parent window if we're in an iframe
      this.notifyParent();
    } catch (error) {
      console.error('Error during logout callback:', error);
      this.message = 'Logout completed';
    }
  }

  private clearStorage(): void {
    // Clear localStorage items related to auth
    const authKeys = [
      'access_token',
      'id_token',
      'refresh_token',
      'expires_at',
      'token_type',
      'nonce',
      'PKCE_verifier',
      'session_state'
    ];

    authKeys.forEach(key => {
      localStorage.removeItem(key);
      sessionStorage.removeItem(key);
    });

    // Also clear any OAuth2-OIDC library storage
    const oauthKeys = Object.keys(localStorage).filter(key =>
      key.startsWith('oauth') ||
      key.startsWith('oidc') ||
      key.includes('token') ||
      key.includes('session')
    );

    oauthKeys.forEach(key => {
      localStorage.removeItem(key);
    });

    const sessionOauthKeys = Object.keys(sessionStorage).filter(key =>
      key.startsWith('oauth') ||
      key.startsWith('oidc') ||
      key.includes('token') ||
      key.includes('session')
    );

    sessionOauthKeys.forEach(key => {
      sessionStorage.removeItem(key);
    });
  }

  private clearCookies(): void {
    // Clear any cookies we can access (same-origin only)
    const cookies = document.cookie.split(';');

    for (const cookie of cookies) {
      const [name] = cookie.split('=');
      if (name) {
        document.cookie = `${name.trim()}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
      }
    }
  }

  private notifyParent(): void {
    // If loaded in an iframe, notify the parent window
    if (window.parent !== window) {
      const parentOrigin = this.getParentOrigin();
      if (!parentOrigin) {
        return;
      }

      try {
        window.parent.postMessage({ type: 'logout-complete' }, parentOrigin);
      } catch {
        // Cross-origin restrictions may prevent this
      }
    }
  }

  private getParentOrigin(): string | null {
    try {
      if (document.referrer) {
        const referrerUrl = new URL(document.referrer);
        return referrerUrl.origin;
      }
    } catch {
      // Ignore malformed referrer URLs
    }
    return null;
  }
}
