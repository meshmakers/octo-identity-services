# Concept: Angular-based Identity Server UI with LCARS Theme

**Created:** 2026-01-22
**Status:** Approved
**Version:** 1.0

---

## 1. Overview

### Decisions

| Aspect | Decision |
|--------|----------|
| Architecture | Angular SPA |
| Component Library | Kendo UI |
| Project Location | `octo-identity-services/src/IdentityServices/ClientApp/` |
| Hosting | ASP.NET Core SPA Services |
| Frontend Libraries | @meshmakers/* fully integrated |
| Localization | Angular i18n (native) |
| OEM Support | Full (Logo, Colors, App Name) |

### Goals

- Consistent LCARS design matching Refinery Studio
- Reuse of existing @meshmakers/* libraries
- Full OEM customization support
- Multi-tenancy support via tenant ID in routes

---

## 2. Project Structure

```
octo-identity-services/
└── src/IdentityServices/
    ├── ClientApp/                       # NEW: Angular SPA
    │   ├── src/
    │   │   ├── app/
    │   │   │   ├── core/                # Services, Guards, Interceptors
    │   │   │   │   ├── services/
    │   │   │   │   │   ├── auth-api.service.ts
    │   │   │   │   │   ├── oem.service.ts
    │   │   │   │   │   ├── consent-api.service.ts
    │   │   │   │   │   └── device-api.service.ts
    │   │   │   │   ├── guards/
    │   │   │   │   │   └── tenant.guard.ts
    │   │   │   │   ├── interceptors/
    │   │   │   │   │   └── tenant.interceptor.ts
    │   │   │   │   └── models/
    │   │   │   │       ├── login.models.ts
    │   │   │   │       ├── consent.models.ts
    │   │   │   │       └── oem.models.ts
    │   │   │   ├── shared/              # Shared LCARS Components
    │   │   │   │   ├── components/
    │   │   │   │   │   ├── lcars-panel/
    │   │   │   │   │   ├── lcars-header/
    │   │   │   │   │   ├── lcars-footer/
    │   │   │   │   │   ├── lcars-button/
    │   │   │   │   │   ├── external-provider-button/
    │   │   │   │   │   └── scope-list/
    │   │   │   │   └── shared.module.ts
    │   │   │   ├── features/            # Feature Modules
    │   │   │   │   ├── login/
    │   │   │   │   │   ├── login.component.ts
    │   │   │   │   │   ├── login.component.html
    │   │   │   │   │   └── login.component.scss
    │   │   │   │   ├── logout/
    │   │   │   │   │   ├── logout.component.ts
    │   │   │   │   │   └── logged-out.component.ts
    │   │   │   │   ├── consent/
    │   │   │   │   │   └── consent.component.ts
    │   │   │   │   ├── device/
    │   │   │   │   │   ├── device-code.component.ts
    │   │   │   │   │   └── device-confirm.component.ts
    │   │   │   │   ├── manage/
    │   │   │   │   │   ├── profile.component.ts
    │   │   │   │   │   ├── change-password.component.ts
    │   │   │   │   │   └── external-logins.component.ts
    │   │   │   │   ├── grants/
    │   │   │   │   │   └── grants.component.ts
    │   │   │   │   └── error/
    │   │   │   │       └── error.component.ts
    │   │   │   ├── app.component.ts
    │   │   │   ├── app.component.html
    │   │   │   ├── app.component.scss
    │   │   │   ├── app.routes.ts
    │   │   │   └── app.config.ts
    │   │   ├── styles/
    │   │   │   ├── _lcars-variables.scss
    │   │   │   ├── _lcars-mixins.scss
    │   │   │   ├── _lcars-kendo-overrides.scss
    │   │   │   ├── _lcars-components.scss
    │   │   │   └── styles.scss
    │   │   ├── assets/
    │   │   │   ├── i18n/
    │   │   │   │   ├── messages.de.xlf
    │   │   │   │   └── messages.en.xlf
    │   │   │   └── images/
    │   │   ├── environments/
    │   │   │   ├── environment.ts
    │   │   │   └── environment.prod.ts
    │   │   ├── index.html
    │   │   └── main.ts
    │   ├── angular.json
    │   ├── package.json
    │   ├── tsconfig.json
    │   └── tsconfig.app.json
    ├── Controllers/
    │   ├── Api/                         # NEW: API for Angular
    │   │   ├── AuthApiController.cs
    │   │   ├── ConsentApiController.cs
    │   │   ├── DeviceApiController.cs
    │   │   ├── ManageApiController.cs
    │   │   ├── GrantsApiController.cs
    │   │   └── OemApiController.cs
    │   ├── Account/                     # EXISTING (Legacy)
    │   ├── Consent/
    │   └── ...
    └── Views/                           # EXISTING (Fallback/Legacy)
```

---

## 3. Pages & Components

### Phase 1: Auth Flows (Priority)

| Page | Route | Description | LCARS Elements |
|------|-------|-------------|----------------|
| **Login** | `/:tenantId/login` | Username/password + external providers | Panel with glow, provider buttons with icons, gradient header |
| **Logout** | `/:tenantId/logout` | Logout confirmation | Minimal panel with confirm button |
| **Logged Out** | `/:tenantId/logged-out` | After logout | Success display with redirect link, mint accent |
| **Consent** | `/:tenantId/consent` | OAuth2 scope consent | Scope list with checkboxes, Allow/Deny buttons |
| **Device Code** | `/:tenantId/device` | Device code entry | Input field with submit, LCARS keyboard style |
| **Device Confirm** | `/:tenantId/device/confirm` | Device authorization | Scope display, Allow/Deny |
| **Error** | `/:tenantId/error` | Error display | Error panel with bubblegum accent |

### Phase 2: User Management

| Page | Route | Description |
|------|-------|-------------|
| **Profile** | `/:tenantId/manage` | User dashboard with info |
| **Change Password** | `/:tenantId/manage/password` | Change password |
| **Set Password** | `/:tenantId/manage/set-password` | Set initial password |
| **External Logins** | `/:tenantId/manage/logins` | Manage external providers |
| **Grants** | `/:tenantId/grants` | View/revoke app permissions |

### Phase 3: Setup & Admin

| Page | Route | Description |
|------|-------|-------------|
| **Setup** | `/:tenantId/setup` | Initial admin setup |
| **Diagnostics** | `/:tenantId/diagnostics` | Dev tools (development only) |

---

## 4. LCARS Design System

### 4.1 Color Palette

```scss
// _lcars-variables.scss

// === Brand Colors (from Octo Brand Manual) ===
$octo-mint: #64ceb9;           // Primary accent, glow effects
$neo-cyan: #00a8dc;            // Secondary highlights

// === Secondary Colors ===
$indigogo: #546fbd;            // Panel accents
$royal-violet: #6c4da8;        // LCARS-typical accent
$toffee: #da9162;              // Warm accent, warnings
$bubblegum: #ec658f;           // Alerts, errors
$lilac-glow: #c861d6;          // Hover states

// === Neutral Colors ===
$ash-blue: #9292a6;            // Inactive elements, secondary text
$iron-navy: #394555;           // Surface, panels
$deep-sea: #07172b;            // Background (NEVER use pure black!)
$surface-elevated: #1f2e40;    // Elevated surfaces

// === CSS Variables ===
:root {
  // Colors
  --octo-mint: #{$octo-mint};
  --octo-mint-rgb: 100, 206, 185;
  --neo-cyan: #{$neo-cyan};
  --neo-cyan-rgb: 0, 168, 220;
  --deep-sea: #{$deep-sea};
  --iron-navy: #{$iron-navy};
  --surface-elevated: #{$surface-elevated};
  --ash-blue: #{$ash-blue};
  --bubblegum: #{$bubblegum};
  --toffee: #{$toffee};
  --royal-violet: #{$royal-violet};

  // Typography
  --lcars-font-primary: 'Montserrat', 'Roboto', 'Helvetica Neue', sans-serif;
  --lcars-font-mono: 'Roboto Mono', 'Consolas', monospace;

  // Glow Effects
  --lcars-glow-primary: 0 0 10px rgba(100, 206, 185, 0.4);
  --lcars-glow-cyan: 0 0 10px rgba(0, 168, 220, 0.4);
  --lcars-glow-error: 0 0 10px rgba(236, 101, 143, 0.4);

  // Border Radius (asymmetric = LCARS-typical)
  --lcars-radius-sm: 4px;
  --lcars-radius-md: 8px;
  --lcars-radius-lg: 16px;
  --lcars-radius-asymmetric: 4px 16px 16px 4px;
  --lcars-radius-pill: 50px;

  // Panel Styling
  --lcars-panel-border: 1px solid rgba(100, 206, 185, 0.2);
  --lcars-panel-bg: rgba(31, 46, 64, 0.6);

  // Transitions
  --lcars-transition-fast: 150ms ease;
  --lcars-transition-normal: 250ms ease;
}
```

### 4.2 LCARS Mixins

```scss
// _lcars-mixins.scss

@mixin lcars-panel {
  background: var(--surface-elevated);
  border: var(--lcars-panel-border);
  border-radius: var(--lcars-radius-asymmetric);
  box-shadow:
    0 4px 20px rgba(0, 0, 0, 0.3),
    0 0 20px rgba(100, 206, 185, 0.08);
}

@mixin lcars-glow($color: var(--octo-mint)) {
  box-shadow: 0 0 10px rgba($color, 0.4);
}

@mixin lcars-header-bar {
  height: 8px;
  background: linear-gradient(90deg, var(--octo-mint), var(--neo-cyan));
  border-radius: var(--lcars-radius-sm) var(--lcars-radius-sm) 0 0;
}

@mixin lcars-footer-bars {
  display: flex;
  gap: 4px;
  height: 6px;

  .bar-mint {
    flex: 3;
    background: linear-gradient(90deg, var(--octo-mint), var(--neo-cyan));
    border-radius: var(--lcars-radius-sm);
  }

  .bar-violet {
    flex: 1;
    background: var(--royal-violet);
    border-radius: var(--lcars-radius-sm);
  }

  .bar-toffee {
    flex: 1;
    background: var(--toffee);
    border-radius: var(--lcars-radius-sm);
  }
}

@mixin lcars-text-glow($color: var(--octo-mint)) {
  text-shadow: 0 0 10px rgba($color, 0.5);
}

@mixin lcars-uppercase-label {
  text-transform: uppercase;
  letter-spacing: 1px;
  font-size: 0.75rem;
  font-weight: 600;
}
```

### 4.3 Kendo UI Overrides

```scss
// _lcars-kendo-overrides.scss

// === Buttons ===
.k-button {
  font-family: var(--lcars-font-primary);
  border-radius: var(--lcars-radius-sm);
  transition: all var(--lcars-transition-fast);
}

.k-button-solid-primary {
  background: linear-gradient(180deg, rgba($octo-mint, 0.3), rgba($octo-mint, 0.15));
  border: 1px solid rgba($octo-mint, 0.5);
  color: #ffffff;

  &:hover {
    background: linear-gradient(180deg, rgba($octo-mint, 0.4), rgba($octo-mint, 0.25));
    border-color: $octo-mint;
    box-shadow: var(--lcars-glow-primary);
  }

  &:active {
    background: linear-gradient(180deg, rgba($octo-mint, 0.5), rgba($octo-mint, 0.35));
  }

  &:disabled {
    opacity: 0.5;
    background: rgba($ash-blue, 0.2);
    border-color: rgba($ash-blue, 0.3);
  }
}

.k-button-solid-error {
  background: linear-gradient(180deg, rgba($bubblegum, 0.2), rgba($bubblegum, 0.1));
  border: 1px solid rgba($bubblegum, 0.4);
  color: $bubblegum;

  &:hover {
    background: linear-gradient(180deg, rgba($bubblegum, 0.3), rgba($bubblegum, 0.2));
    box-shadow: var(--lcars-glow-error);
  }
}

.k-button-outline-base {
  background: transparent;
  border: 1px solid rgba($ash-blue, 0.5);
  color: $ash-blue;

  &:hover {
    color: $octo-mint;
    border-color: rgba($octo-mint, 0.5);
    background: rgba($octo-mint, 0.1);
    box-shadow: var(--lcars-glow-primary);
  }
}

// === Input Fields ===
.k-textbox,
.k-input {
  background: rgba($deep-sea, 0.8);
  border: 1px solid rgba($ash-blue, 0.3);
  border-radius: var(--lcars-radius-sm);
  color: #ffffff;
  font-family: var(--lcars-font-primary);

  &::placeholder {
    color: rgba($ash-blue, 0.7);
  }

  &:hover {
    border-color: rgba($octo-mint, 0.5);
  }

  &:focus,
  &.k-focus {
    border-color: $octo-mint;
    box-shadow: var(--lcars-glow-primary);
    outline: none;
  }

  &.k-invalid {
    border-color: $bubblegum;

    &:focus {
      box-shadow: var(--lcars-glow-error);
    }
  }
}

// === Checkboxes ===
.k-checkbox {
  border-color: rgba($ash-blue, 0.5);
  background: rgba($deep-sea, 0.8);

  &:checked {
    background: $octo-mint;
    border-color: $octo-mint;
  }

  &:focus {
    box-shadow: var(--lcars-glow-primary);
  }
}

// === Labels ===
.k-label {
  color: $ash-blue;
  font-family: var(--lcars-font-primary);
  @include lcars-uppercase-label;
}
```

---

## 5. Shared Components

### 5.1 LCARS Panel Component

```typescript
// shared/components/lcars-panel/lcars-panel.component.ts
import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-lcars-panel',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="lcars-panel" [class.lcars-panel--error]="variant === 'error'">
      <div class="lcars-panel__header-bar"></div>
      <div class="lcars-panel__content">
        <ng-content></ng-content>
      </div>
      <div class="lcars-panel__footer">
        <div class="bar-mint"></div>
        <div class="bar-violet"></div>
        <div class="bar-toffee"></div>
      </div>
    </div>
  `,
  styleUrl: './lcars-panel.component.scss'
})
export class LcarsPanelComponent {
  @Input() variant: 'default' | 'error' = 'default';
}
```

### 5.2 LCARS Header Component

```typescript
// shared/components/lcars-header/lcars-header.component.ts
import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-lcars-header',
  standalone: true,
  imports: [CommonModule],
  template: `
    <header class="lcars-header">
      <div class="lcars-header__accent-bar"></div>
      <div class="lcars-header__content">
        <div class="lcars-header__title">
          <span class="title-primary">{{ primaryText }}</span>
          <span class="title-secondary" *ngIf="secondaryText">{{ secondaryText }}</span>
        </div>
        <img *ngIf="logoUrl" [src]="logoUrl" [alt]="appName" class="lcars-header__logo" />
      </div>
    </header>
  `,
  styleUrl: './lcars-header.component.scss'
})
export class LcarsHeaderComponent {
  @Input() primaryText = 'OCTO';
  @Input() secondaryText = 'IDENTITY';
  @Input() logoUrl?: string;
  @Input() appName = 'Octo Identity';
}
```

### 5.3 External Provider Button Component

```typescript
// shared/components/external-provider-button/external-provider-button.component.ts
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ButtonModule } from '@progress/kendo-angular-buttons';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import {
  faGoogle, faMicrosoft, faFacebook, faApple
} from '@fortawesome/free-brands-svg-icons';
import { faServer } from '@fortawesome/free-solid-svg-icons';

@Component({
  selector: 'app-external-provider-button',
  standalone: true,
  imports: [CommonModule, ButtonModule, FontAwesomeModule],
  template: `
    <button kendoButton
            [look]="'outline'"
            class="provider-button"
            [class]="'provider-' + provider.scheme.toLowerCase()"
            (click)="onLogin()">
      <fa-icon [icon]="getIcon()"></fa-icon>
      <span>{{ provider.displayName }}</span>
    </button>
  `,
  styleUrl: './external-provider-button.component.scss'
})
export class ExternalProviderButtonComponent {
  @Input() provider!: { scheme: string; displayName: string };
  @Output() login = new EventEmitter<string>();

  icons = { faGoogle, faMicrosoft, faFacebook, faApple, faServer };

  getIcon() {
    const scheme = this.provider.scheme.toLowerCase();
    return this.icons[`fa${this.capitalize(scheme)}`] || this.icons.faServer;
  }

  onLogin() {
    this.login.emit(this.provider.scheme);
  }

  private capitalize(s: string) {
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
}
```

### 5.4 Scope List Component

```typescript
// shared/components/scope-list/scope-list.component.ts
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CheckBoxModule } from '@progress/kendo-angular-inputs';

export interface ScopeItem {
  name: string;
  displayName: string;
  description?: string;
  required: boolean;
  checked: boolean;
}

@Component({
  selector: 'app-scope-list',
  standalone: true,
  imports: [CommonModule, FormsModule, CheckBoxModule],
  template: `
    <div class="scope-list">
      <div class="scope-list__header">
        <span class="scope-list__title">{{ title }}</span>
      </div>
      <div class="scope-list__items">
        <div *ngFor="let scope of scopes" class="scope-item">
          <kendo-checkbox
            [(ngModel)]="scope.checked"
            [disabled]="scope.required"
            (checkedChange)="onScopeChange()">
          </kendo-checkbox>
          <div class="scope-item__content">
            <span class="scope-item__name">{{ scope.displayName }}</span>
            <span *ngIf="scope.description" class="scope-item__description">
              {{ scope.description }}
            </span>
            <span *ngIf="scope.required" class="scope-item__required">Required</span>
          </div>
        </div>
      </div>
    </div>
  `,
  styleUrl: './scope-list.component.scss'
})
export class ScopeListComponent {
  @Input() title = 'Requested Permissions';
  @Input() scopes: ScopeItem[] = [];
  @Output() scopesChange = new EventEmitter<ScopeItem[]>();

  onScopeChange() {
    this.scopesChange.emit(this.scopes);
  }
}
```

---

## 6. API Endpoints (ASP.NET Backend)

### 6.1 Auth API Controller

```csharp
// Controllers/Api/AuthApiController.cs
[ApiController]
[Route("{tenantId}/api/auth")]
public class AuthApiController : ControllerBase
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IAuthenticationSchemeProvider _schemeProvider;

    [HttpGet("login-context")]
    public async Task<ActionResult<LoginContextDto>> GetLoginContext(
        [FromQuery] string returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        return new LoginContextDto
        {
            ReturnUrl = returnUrl,
            ClientName = context?.Client?.ClientName,
            ClientLogoUrl = context?.Client?.LogoUri,
            ExternalProviders = await GetExternalProviders(context),
            AllowRememberLogin = true,
            EnableLocalLogin = context?.Client?.EnableLocalLogin ?? true
        };
    }

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult<LoginResultDto>> Login(
        [FromBody] LoginRequest request)
    {
        // Validate credentials
        // Sign in user
        // Return result with redirect URL
    }

    [HttpGet("external-providers")]
    public async Task<ActionResult<IEnumerable<ExternalProviderDto>>> GetExternalProviders()
    {
        var schemes = await _schemeProvider.GetAllSchemesAsync();
        return schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ExternalProviderDto
            {
                Scheme = x.Name,
                DisplayName = x.DisplayName
            })
            .ToList();
    }

    [HttpGet("logout-context")]
    public async Task<ActionResult<LogoutContextDto>> GetLogoutContext(
        [FromQuery] string logoutId)
    {
        var context = await _interaction.GetLogoutContextAsync(logoutId);
        return new LogoutContextDto
        {
            LogoutId = logoutId,
            ShowLogoutPrompt = context?.ShowSignoutPrompt ?? true,
            PostLogoutRedirectUri = context?.PostLogoutRedirectUri
        };
    }

    [HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult<LogoutResultDto>> Logout(
        [FromBody] LogoutRequest request)
    {
        // Sign out user
        // Return result
    }
}
```

### 6.2 Consent API Controller

```csharp
// Controllers/Api/ConsentApiController.cs
[ApiController]
[Route("{tenantId}/api/consent")]
public class ConsentApiController : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<ConsentContextDto>> GetConsentContext(
        [FromQuery] string returnUrl)
    {
        var request = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (request == null) return NotFound();

        return new ConsentContextDto
        {
            ReturnUrl = returnUrl,
            ClientName = request.Client.ClientName,
            ClientUrl = request.Client.ClientUri,
            ClientLogoUrl = request.Client.LogoUri,
            IdentityScopes = GetIdentityScopes(request),
            ApiScopes = GetApiScopes(request),
            AllowRememberConsent = request.Client.AllowRememberConsent
        };
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult<ConsentResultDto>> ProcessConsent(
        [FromBody] ConsentRequest request)
    {
        // Process consent decision
        // Grant or deny
    }
}
```

### 6.3 OEM API Controller

```csharp
// Controllers/Api/OemApiController.cs
[ApiController]
[Route("{tenantId}/api/oem")]
public class OemApiController : ControllerBase
{
    private readonly IOemService _oemService;

    [HttpGet("config")]
    [ResponseCache(Duration = 300)]
    public ActionResult<OemConfigDto> GetOemConfig()
    {
        return new OemConfigDto
        {
            AppName = _oemService.ApplicationName,
            LogoUrl = _oemService.LogoUrl,
            FaviconUrl = _oemService.FaviconUrl,
            PrimaryColor = _oemService.PrimaryColor,
            AccentColor = _oemService.AccentColor,
            HideNavigation = _oemService.HideNavigation
        };
    }
}
```

### 6.4 DTOs

```csharp
// Models/Api/LoginContextDto.cs
public record LoginContextDto
{
    public string ReturnUrl { get; init; }
    public string? ClientName { get; init; }
    public string? ClientLogoUrl { get; init; }
    public IEnumerable<ExternalProviderDto> ExternalProviders { get; init; }
    public bool AllowRememberLogin { get; init; }
    public bool EnableLocalLogin { get; init; }
}

public record LoginRequest
{
    public string Username { get; init; }
    public string Password { get; init; }
    public bool RememberLogin { get; init; }
    public string ReturnUrl { get; init; }
}

public record LoginResultDto
{
    public bool Success { get; init; }
    public string? RedirectUrl { get; init; }
    public string? ErrorMessage { get; init; }
}

public record ExternalProviderDto
{
    public string Scheme { get; init; }
    public string DisplayName { get; init; }
}

public record OemConfigDto
{
    public string AppName { get; init; }
    public string? LogoUrl { get; init; }
    public string? FaviconUrl { get; init; }
    public string? PrimaryColor { get; init; }
    public string? AccentColor { get; init; }
    public bool HideNavigation { get; init; }
}
```

---

## 7. Angular Services

### 7.1 Auth API Service

```typescript
// core/services/auth-api.service.ts
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { LoginContext, LoginRequest, LoginResult } from '../models/login.models';

@Injectable({ providedIn: 'root' })
export class AuthApiService {
  private http = inject(HttpClient);

  getLoginContext(returnUrl: string): Observable<LoginContext> {
    return this.http.get<LoginContext>('/api/auth/login-context', {
      params: { returnUrl }
    });
  }

  login(request: LoginRequest): Observable<LoginResult> {
    return this.http.post<LoginResult>('/api/auth/login', request);
  }

  getExternalProviders(): Observable<ExternalProvider[]> {
    return this.http.get<ExternalProvider[]>('/api/auth/external-providers');
  }

  getLogoutContext(logoutId: string): Observable<LogoutContext> {
    return this.http.get<LogoutContext>('/api/auth/logout-context', {
      params: { logoutId }
    });
  }

  logout(request: LogoutRequest): Observable<LogoutResult> {
    return this.http.post<LogoutResult>('/api/auth/logout', request);
  }
}
```

### 7.2 OEM Service

```typescript
// core/services/oem.service.ts
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { OemConfig } from '../models/oem.models';

const defaultConfig: OemConfig = {
  appName: 'Octo Identity',
  logoUrl: '/assets/images/logo.svg',
  hideNavigation: false
};

@Injectable({ providedIn: 'root' })
export class OemService {
  private http = inject(HttpClient);
  private config$ = new BehaviorSubject<OemConfig>(defaultConfig);

  readonly config = this.config$.asObservable();

  loadConfig(): Observable<OemConfig> {
    return this.http.get<OemConfig>('/api/oem/config').pipe(
      tap(config => {
        this.config$.next(config);
        this.applyThemeOverrides(config);
        this.updateFavicon(config.faviconUrl);
        this.updateTitle(config.appName);
      })
    );
  }

  private applyThemeOverrides(config: OemConfig): void {
    const root = document.documentElement;

    if (config.primaryColor) {
      root.style.setProperty('--octo-mint', config.primaryColor);
      // Calculate RGB values for rgba() usage
      const rgb = this.hexToRgb(config.primaryColor);
      if (rgb) {
        root.style.setProperty('--octo-mint-rgb', `${rgb.r}, ${rgb.g}, ${rgb.b}`);
      }
    }

    if (config.accentColor) {
      root.style.setProperty('--neo-cyan', config.accentColor);
    }
  }

  private hexToRgb(hex: string): { r: number; g: number; b: number } | null {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16)
    } : null;
  }

  private updateFavicon(url?: string): void {
    if (url) {
      const link = document.querySelector("link[rel*='icon']") as HTMLLinkElement;
      if (link) link.href = url;
    }
  }

  private updateTitle(appName: string): void {
    document.title = appName;
  }
}
```

### 7.3 Tenant Interceptor

```typescript
// core/interceptors/tenant.interceptor.ts
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

export const tenantInterceptor: HttpInterceptorFn = (req, next) => {
  const route = inject(ActivatedRoute);
  const tenantId = route.snapshot.params['tenantId'] || 'System';

  // Prepend tenant ID to API calls
  if (req.url.startsWith('/api/')) {
    const tenantUrl = `/${tenantId}${req.url}`;
    req = req.clone({ url: tenantUrl });
  }

  return next(req);
};
```

---

## 8. Routing

```typescript
// app.routes.ts
import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: ':tenantId',
    children: [
      {
        path: 'login',
        loadComponent: () => import('./features/login/login.component')
          .then(m => m.LoginComponent)
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
  }
];
```

---

## 9. ASP.NET Integration

### 9.1 Program.cs Changes

```csharp
// Program.cs

// Configure SPA Static Files
builder.Services.AddSpaStaticFiles(configuration =>
{
    configuration.RootPath = "ClientApp/dist/identity-ui/browser";
});

// In the pipeline (after UseRouting, before UseEndpoints)
app.UseStaticFiles();
app.UseSpaStaticFiles();

// API and IdentityServer Endpoints
app.MapControllers();

// SPA Fallback for all other routes
app.MapWhen(
    context => !context.Request.Path.StartsWithSegments("/api") &&
               !context.Request.Path.StartsWithSegments("/connect") &&
               !context.Request.Path.StartsWithSegments("/.well-known"),
    builder =>
    {
        builder.UseSpa(spa =>
        {
            spa.Options.SourcePath = "ClientApp";

            if (app.Environment.IsDevelopment())
            {
                spa.UseAngularCliServer(npmScript: "start");
            }
        });
    });
```

### 9.2 csproj Changes

```xml
<!-- IdentityServices.csproj -->
<PropertyGroup>
  <SpaRoot>ClientApp\</SpaRoot>
  <SpaProxyServerUrl>https://localhost:44400</SpaProxyServerUrl>
</PropertyGroup>

<ItemGroup>
  <PackageReference Include="Microsoft.AspNetCore.SpaServices.Extensions" Version="9.0.0" />
</ItemGroup>

<Target Name="PublishAngular" AfterTargets="ComputeFilesToPublish">
  <Exec WorkingDirectory="$(SpaRoot)" Command="npm install" />
  <Exec WorkingDirectory="$(SpaRoot)" Command="npm run build -- --configuration production" />

  <ItemGroup>
    <DistFiles Include="$(SpaRoot)dist\identity-ui\browser\**" />
    <ResolvedFileToPublish Include="@(DistFiles)">
      <RelativePath>%(DistFiles.RecursiveDir)%(DistFiles.Filename)%(DistFiles.Extension)</RelativePath>
      <CopyToPublishDirectory>PreserveNewest</CopyToPublishDirectory>
    </ResolvedFileToPublish>
  </ItemGroup>
</Target>
```

---

## 10. Dependencies

### 10.1 package.json

```json
{
  "name": "identity-ui",
  "version": "0.0.0",
  "scripts": {
    "ng": "ng",
    "start": "ng serve --ssl --port 44400",
    "build": "ng build",
    "watch": "ng build --watch --configuration development",
    "test": "ng test",
    "lint": "ng lint",
    "extract-i18n": "ng extract-i18n"
  },
  "dependencies": {
    "@angular/animations": "^19.0.0",
    "@angular/common": "^19.0.0",
    "@angular/compiler": "^19.0.0",
    "@angular/core": "^19.0.0",
    "@angular/forms": "^19.0.0",
    "@angular/platform-browser": "^19.0.0",
    "@angular/platform-browser-dynamic": "^19.0.0",
    "@angular/router": "^19.0.0",
    "@progress/kendo-angular-buttons": "^19.0.0",
    "@progress/kendo-angular-inputs": "^19.0.0",
    "@progress/kendo-angular-layout": "^19.0.0",
    "@progress/kendo-angular-icons": "^19.0.0",
    "@progress/kendo-angular-l10n": "^19.0.0",
    "@progress/kendo-angular-common": "^19.0.0",
    "@progress/kendo-licensing": "^1.0.0",
    "@fortawesome/angular-fontawesome": "^0.15.0",
    "@fortawesome/fontawesome-svg-core": "^6.5.0",
    "@fortawesome/free-brands-svg-icons": "^6.5.0",
    "@fortawesome/free-solid-svg-icons": "^6.5.0",
    "@meshmakers/shared-ui": "workspace:*",
    "@meshmakers/octo-auth": "workspace:*",
    "rxjs": "~7.8.0",
    "tslib": "^2.6.0",
    "zone.js": "~0.14.0"
  },
  "devDependencies": {
    "@angular-devkit/build-angular": "^19.0.0",
    "@angular/cli": "^19.0.0",
    "@angular/compiler-cli": "^19.0.0",
    "@types/node": "^20.0.0",
    "typescript": "~5.6.0"
  }
}
```

---

## 11. Migration Strategy

### Phase 1: Setup & Login (Sprint 1)

| Task | Description |
|------|-------------|
| 1.1 | Create Angular project in ClientApp |
| 1.2 | Port LCARS SCSS variables and mixins from Refinery Studio |
| 1.3 | Implement Kendo UI overrides |
| 1.4 | Create shared components (Panel, Header, Footer) |
| 1.5 | Implement AuthApiController and OemApiController |
| 1.6 | Login page with local login and external providers |
| 1.7 | ASP.NET SPA integration |

### Phase 2: Auth Flows (Sprint 1-2)

| Task | Description |
|------|-------------|
| 2.1 | Logout and LoggedOut pages |
| 2.2 | Consent page with scope list |
| 2.3 | Device Authorization flow (code entry, confirmation) |
| 2.4 | Error page |
| 2.5 | i18n setup (DE, EN) |

### Phase 3: OEM & Polish (Sprint 2)

| Task | Description |
|------|-------------|
| 3.1 | Full OEM customization integration |
| 3.2 | Test and adjust responsive design |
| 3.3 | Accessibility audit |
| 3.4 | E2E tests |

### Phase 4: User Management (Sprint 3)

| Task | Description |
|------|-------------|
| 4.1 | Profile page |
| 4.2 | Password change/set |
| 4.3 | Manage external logins |
| 4.4 | Grants page |

### Phase 5: Cleanup (Sprint 3)

| Task | Description |
|------|-------------|
| 5.1 | Remove old Razor Views |
| 5.2 | Convert old controllers to API-only |
| 5.3 | Update documentation |

---

## 12. Design Mockups

### Login Page

```
┌─────────────────────────────────────────────────────────────┐
│ ████████████████████████████████████████████████████████████│ ← Gradient Bar (Mint→Cyan)
│                                                             │
│                      ┌─────────────────┐                    │
│                      │   [OEM LOGO]    │                    │
│                      └─────────────────┘                    │
│                                                             │
│              ╭──────────────────────────────╮               │
│              │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ │ ← Panel Header
│              │                              │               │
│              │  OCTO IDENTITY               │               │
│              │  Sign in to continue         │               │
│              │                              │               │
│              │  ┌────────────────────────┐  │               │
│              │  │ Username               │  │               │
│              │  └────────────────────────┘  │               │
│              │  ┌────────────────────────┐  │               │
│              │  │ Password               │  │               │
│              │  └────────────────────────┘  │               │
│              │                              │               │
│              │  ☐ Remember me               │               │
│              │                              │               │
│              │  ┌────────────────────────┐  │               │
│              │  │      SIGN IN ━━━━►     │  │ ← Mint Button
│              │  └────────────────────────┘  │               │
│              │                              │               │
│              │  ────── or continue with ─── │               │
│              │                              │               │
│              │  ┌──────┐ ┌──────┐ ┌──────┐  │               │
│              │  │Google│ │Azure │ │ LDAP │  │ ← Provider Btns
│              │  └──────┘ └──────┘ └──────┘  │               │
│              │                              │               │
│              │ ▓▓▓▓▓▓▓▓▓▓ ▓▓▓ ▓▓▓           │ ← Footer Bars
│              ╰──────────────────────────────╯               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Consent Page

```
┌─────────────────────────────────────────────────────────────┐
│ ████████████████████████████████████████████████████████████│
│                                                             │
│              ╭──────────────────────────────╮               │
│              │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ │               │
│              │                              │               │
│              │  [App Logo]  App Name        │               │
│              │  wants to access your data   │               │
│              │                              │               │
│              │  REQUESTED PERMISSIONS       │               │
│              │  ─────────────────────────   │               │
│              │  ☑ Your profile information  │               │
│              │  ☑ Your email address        │               │
│              │  ☐ Offline access            │               │
│              │                              │               │
│              │  ☐ Remember my decision      │               │
│              │                              │               │
│              │  ┌──────────┐  ┌──────────┐  │               │
│              │  │  ALLOW   │  │  DENY    │  │               │
│              │  └──────────┘  └──────────┘  │               │
│              │                              │               │
│              │ ▓▓▓▓▓▓▓▓▓▓ ▓▓▓ ▓▓▓           │               │
│              ╰──────────────────────────────╯               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 13. Open Items

- [ ] Clarify Kendo UI license for Identity project
- [ ] Decision: Should Setup page also be migrated?
- [ ] Decision: Migrate Diagnostics page (dev-only)?
- [ ] @meshmakers/* libraries: Which version to use?
- [ ] Adapt CI/CD pipeline for ClientApp

---

## Appendix: References

- **Refinery Studio LCARS Theme**: `/octo-frontend-refinery-studio/src/octo-mesh-refinery-studio/src/styles.scss`
- **Refinery Studio CLAUDE.md**: `/octo-frontend-refinery-studio/src/octo-mesh-refinery-studio/CLAUDE.md` (lines 201-821)
- **Current Identity UI**: `/octo-identity-services/src/IdentityServices/Views/`
- **Octo Brand Manual**: Defines color palette and typography
