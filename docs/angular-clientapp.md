---
description: "Angular ClientApp (LCARS UI): build, lint, toolchain, device flow, i18n, SPA version, API controllers"
applies_to: "src/IdentityServices/ClientApp/**"
---

# Angular ClientApp (LCARS UI)

The Identity Services includes an Angular SPA frontend in `src/IdentityServices/ClientApp/` with LCARS theme styling.

## Angular Build Commands

```bash
cd src/IdentityServices/ClientApp

# Install dependencies
npm install

# Development server
npm start

# Production build
npm run build

# Linting (REQUIRED before every commit)
npm run lint
```

## Linting (REQUIRED)

**CRITICAL: Always run the linter before every commit!**

```bash
cd src/IdentityServices/ClientApp
npx ng lint
```

The CI/CD pipeline will fail if there are any lint errors. Common issues:
- **Unused imports**: Run with `--fix` flag to auto-remove (`npx ng lint --fix`)
- **Unused variables**: Prefix with `_` (e.g., `_unusedParam`)
- **Empty functions**: Add a comment or remove the empty function

## Toolchain

- Build, serve and extract-i18n run on `@angular/build` (esbuild/Vite); `@angular-devkit/build-angular`
  is gone. The `application` builder writes a **flat `dist/`** (`outputPath.browser: ""`) because
  `IdentityServices.csproj` copies `ClientApp/dist/**` to `wwwroot` and checks for `dist/index.html`.
- Unit tests: Vitest on jsdom via `@angular/build:unit-test` (same setup as Refinery Studio).
  Run `npm test` (= `ng test --watch=false`) in `ClientApp`; a single spec:
  `npm test -- --include='**/device-confirm.component.spec.ts'`. Never call `npx vitest` directly.
  Specs live next to the component (`*.spec.ts`), `tsconfig.spec.json` pulls in `vitest/globals`.
- `allowScripts` in `package.json` lists the six packages npm >= 11.16 may run install scripts for
  (`esbuild`, `lmdb`, `msgpackr-extract`, `@parcel/watcher`, `fsevents`, `@progress/kendo-licensing`).
  A new dependency with an install script produces an `npm warn allow-scripts` line until it is
  approved with `npm approve-scripts --no-allow-scripts-pin <pkg>`. `fsevents` is macOS-only and only
  shows up as pending on a clean install.
- No `.npmrc`: the lockfile resolves without `legacy-peer-deps`. If `npm install` reports `ERESOLVE`,
  fix the peer conflict instead of restoring the flag.
- The only deprecation `npm install` still prints is `@angular/animations`: peer-required and imported
  at runtime by Kendo 24, it stays until Kendo drops it (same as every other Meshmakers Angular app).
  `@angular/platform-browser-dynamic` was removed (unused since the standalone bootstrap in `main.ts`).
- Expected result of a clean `npm ci` + `npm run build`: no allow-scripts advisory, no other
  deprecation, 0 vulnerabilities, no build warnings.

## Device flow loop guard

`/{tenant}/device/confirm` loads `GET /connect/deviceverification` (tenant-free URL; the tenant comes
from the tenant hint `acr_values=tenant:{tenantId}` the page sends; fallback system
tenant). On 401 it navigates **once** to `/{tenant}/login` with a `loginAttempted=1` marker inside the
`returnUrl`; the login page's "already signed in" shortcut sends an authenticated user straight
back. If the endpoint still answers 401 with the marker present, the page stops and shows
`DEVICE.ERROR_SESSION_REJECTED` (EN/DE) instead of bouncing forever. The consent page has no 401
redirect and `AuthorizeController` strips `prompt=login` and signs out stale sessions, so neither loops.

## Device confirm feedback

`POST /connect/deviceverification` always answers **HTTP 200** with `{ success, errorMessage, error }`
(`OctoDeviceVerificationResponseHandler`; `error` is the OAuth code: `access_denied` = denied by the user
or cross-tenant refused, `invalid_token` = code used/expired/unknown). `DeviceVerificationController` also
returns that shape itself for a code that is not pending any more. `GET` answers 404 for such a code.
"Pending" = the user code token (`principal.GetTokenId()`) still has status `valid`: OpenIddict keeps
authenticating an approved/denied code on the verification endpoint, and a second `SignIn` for it throws
(HTTP 500), so the controller checks the status itself (`IsUserCodePendingAsync`). Never use `Forbid` for
the unknown-code case: the challenge handler needs an authenticated principal and throws.
The page always ends in a visible state: success, denied (`DEVICE.DENIED`), or an error
(`DEVICE.ERROR_CODE_USED`, `ERROR_SESSION_REJECTED`, `ERROR_NO_CONFIRMATION` for a 2xx/unparsable body of
unknown outcome, server text for e.g. cross-tenant). Terminal errors hide the consent dialog; retryable
ones (HTTP 5xx, cross-tenant refusal) show a banner above the buttons. Specs:
`device-confirm.feedback.spec.ts`, `OctoDeviceVerificationResponseHandlerTests`,
`DeviceVerificationFeedbackTests`.

## Angular Project Structure

- `src/app/core/` - Services, interceptors, models
- `src/app/shared/` - Reusable LCARS components (lcars-panel, lcars-header, etc.)
- `src/app/features/` - Feature components (login, logout, consent, device, manage, grants, error, setup)
- `src/styles/` - LCARS design system (variables, mixins, Kendo overrides)

## i18n

The ClientApp is fully internationalized with **@ngx-translate/core 17** — the same library and
pattern as the meshmakers-app (custom `TranslateLoader` over `HttpClient` in `app.config.ts`, no
`@ngx-translate/http-loader` package). Resources live in `src/assets/i18n/en.json` and `de.json`
(nested `GROUP.KEY` structure, one group per feature, keys **sorted alphabetically**; EN and DE key
sets must stay identical). `LanguageService` (`core/services/language.service.ts`) picks the
initial language: persisted override in `localStorage['identity-ui.language']` → browser language
(prefix match en/de) → `en`; the EN/DE switcher sits in the `lcars-header` top-right corner and
persists the choice. Translations are loaded in the app initializer **before** first render, so
`translate.instant(...)` is safe in every TypeScript code path. Rules:

- Every user-facing string goes through the `translate` pipe (templates) or
  `TranslateService.instant` (TS error/success paths) — never hardcode UI text.
- Backend-provided messages (`result.errorMessage`, `error.error?.message`, scope display
  names/descriptions, provider/client display names, server validation `errors[]`) are rendered
  as-is; client-side keys only serve as fallbacks when the backend sends nothing.
- German is professional Sie-Form.
- Never JSON-roundtrip the i18n files with tooling — edit them textually (preserves ordering and
  diffs).

## SPA Version Display

The version label in the dialog footer (`lcars-panel`) comes from
`src/environments/currentVersion.ts`, generated by `src/environments/version.ts`
(runs on npm `postinstall` and explicitly from the MSBuild SPA targets). The
generator prefers the `OCTO_VERSION` environment variable — injected by
`BuildClientApp` / `PublishRunWebpack` in `IdentityServices.csproj` as
`$(OctoServiceVersion)` — and falls back to `package.json` (`0.0.0`) when the
variable is unset or a wildcard NuGet pin (`0.1.*` / `3.4.*`).

`OctoServiceVersion` is fed by the CI Docker build as the
`OCTO_SERVICE_VERSION` build arg carrying `$(Build.BuildNumber)` (see
`azure-pipelines.yml` extraBuildArgs), matching the .NET InformationalVersion.
**Do not use `$(OctoVersion)` for display**: on main/dev/test CI builds
update-build-number.yml deliberately sets it to the floating NuGet pin
`0.1.*`; it is exact only on r-tag builds. When `OctoServiceVersion` is not
provided it falls back to `$(OctoVersion)`, so local DebugL builds show
`v999.0.0`. Never edit `currentVersion.ts` manually.

## API Controllers for Angular SPA

Located in `Controllers/Api/`:
- `AuthApiController` - Login, logout, external providers, cross-tenant auth, cross-tenant auto-login (token-based), tenant switch
- `ConsentApiController` - OAuth consent flow; its device methods drive the OpenIddict end-user verification endpoint (`/connect/deviceverification`, form-encoded) via the SPA's `ConsentApiService`
- `DeviceApiController` - Holds the device-flow DTOs only (the flow itself runs through `/connect/deviceverification`)
- `ManageApiController` - User profile, password, external logins
- `MyIdentifiersApiController` - Self-service verified identifiers (phone/e-mail OTP, certificate) at `{tenantId}/api/manage/identifiers`, plus the preferred outbound channel (`GET`/`PUT .../preferredChannel`); accepts cookie AND bearer schemes
- `GrantsApiController` - OAuth grants management
- `OemApiController` - OEM configuration
- `SetupApiController` - Anonymous initial admin user setup (returns 404 after setup complete)
