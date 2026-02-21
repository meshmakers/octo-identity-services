# Konzept: Two-Factor Authentication (2FA)

## Status: Entscheidungen getroffen - Bereit zur Implementierung

## 1. Ist-Zustand

### Was bereits existiert:
- `RtUser.TwoFactorEnabled` Flag im Datenmodell
- Login-Endpoint erkennt 2FA-Anforderung und gibt `RequiresTwoFactor = true` zurück
- `AddDefaultTokenProviders()` registriert die Standard ASP.NET Core Identity Token Provider:
  - Email Token Provider
  - Phone Number Token Provider
  - Authenticator Token Provider (TOTP für Apps wie Google Authenticator)

### Was fehlt:
1. **Kein 2FA-Setup-Endpoint** - Benutzer können 2FA nicht aktivieren
2. **Kein 2FA-Login-Endpoint** - Nach `RequiresTwoFactor = true` gibt es keinen Weg, den 2FA-Code einzugeben
3. **Keine Angular UI** für 2FA-Setup oder 2FA-Login
4. **Keine Recovery Codes** - Für den Fall, dass der Authenticator verloren geht

## 2. Geplante Architektur

### 2.1 Unterstützte 2FA-Methoden (Phase 1)

| Methode | Beschreibung | Status |
|---------|--------------|--------|
| **TOTP Authenticator** | Google Authenticator, Microsoft Authenticator, etc. | ✅ Phase 1 |
| **Email Code** | Code per E-Mail senden (wenn konfiguriert) | ✅ Phase 1 |
| **Recovery Codes** | 10 Einmal-Codes für Notfälle | ✅ Phase 1 |
| **Remember Machine** | 2FA für X Tage überspringen | ✅ Phase 1 |
| ~~SMS Code~~ | Code per SMS senden | ❌ Nicht geplant |
| **Erzwungene 2FA** | 2FA-Pflicht für bestimmte Rollen | 📋 Phase 2 |

### 2.2 API Endpoints

#### Setup Endpoints (ManageApiController)

```
GET  /api/manage/2fa/status
     → { enabled: bool, hasAuthenticator: bool, recoveryCodesLeft: int }

POST /api/manage/2fa/authenticator/setup
     → { sharedKey: string, qrCodeUri: string }

POST /api/manage/2fa/authenticator/verify
     ← { code: string }
     → { success: bool, recoveryCodes: string[] }

POST /api/manage/2fa/disable
     ← { code: string }
     → { success: bool }

POST /api/manage/2fa/recovery-codes/generate
     → { recoveryCodes: string[] }
```

#### Login Endpoints (AuthApiController)

```
POST /api/auth/login-2fa
     ← { code: string, rememberMachine: bool }
     → { success: bool, redirectUrl: string }

POST /api/auth/login-recovery
     ← { recoveryCode: string }
     → { success: bool, redirectUrl: string }
```

### 2.3 Angular UI Komponenten

```
features/
├── manage/
│   └── two-factor/
│       ├── two-factor-setup.component.ts    # QR-Code anzeigen, Code verifizieren
│       ├── two-factor-status.component.ts   # 2FA aktivieren/deaktivieren
│       └── recovery-codes.component.ts      # Recovery Codes anzeigen/generieren
└── login/
    └── two-factor-login.component.ts        # 2FA-Code eingeben beim Login
```

### 2.4 Datenbank-Änderungen

Das `RtUser` Model benötigt möglicherweise zusätzliche Felder:

```yaml
# ConstructionKit/System.Identity-1.0.0/types/User.yaml
attributes:
  # Bereits vorhanden:
  - TwoFactorEnabled: bool

  # Möglicherweise neu (prüfen ob durch Identity abstrahiert):
  - AuthenticatorKey: string?        # Geheimer Schlüssel für TOTP
  - RecoveryCodesHash: string?       # Gehashte Recovery Codes
```

**Frage:** Werden diese Felder von ASP.NET Core Identity automatisch in separaten Tabellen/Collections gespeichert, oder müssen wir sie explizit im Model definieren?

## 3. Integration Tests für 2FA

### 3.1 Ansatz 1: Echte TOTP-Codes generieren

```csharp
// NuGet: Otp.NET
using OtpNet;

public async Task Login_WithTwoFactor_And_ValidCode_Succeeds()
{
    // 1. User mit 2FA erstellen
    var user = await CreateTestUserAsync(userName, password: password);

    // 2. Authenticator Key setzen
    var key = KeyGeneration.GenerateRandomKey(20);
    var base32Key = Base32Encoding.ToString(key);
    await userManager.SetAuthenticationTokenAsync(user,
        "[AspNetUserStore]", "AuthenticatorKey", base32Key);
    await userManager.SetTwoFactorEnabledAsync(user, true);

    // 3. Login (gibt RequiresTwoFactor zurück)
    var loginResult = await LoginAsync(userName, password);
    loginResult.RequiresTwoFactor.Should().BeTrue();

    // 4. TOTP-Code generieren
    var totp = new Totp(key);
    var code = totp.ComputeTotp();

    // 5. 2FA-Login
    var result = await Login2faAsync(code);
    result.Success.Should().BeTrue();
}
```

**Vorteile:**
- Testet den echten Flow
- Keine Mocks nötig

**Nachteile:**
- Abhängigkeit von Otp.NET NuGet Package
- Zeitabhängig (TOTP-Codes sind nur 30 Sekunden gültig)

### 3.2 Ansatz 2: Test Token Provider

```csharp
// In CustomWebApplicationFactory
services.Configure<IdentityOptions>(options =>
{
    options.Tokens.AuthenticatorTokenProvider = "TestAuthenticator";
});
services.AddTransient<IUserTwoFactorTokenProvider<RtUser>, TestTwoFactorTokenProvider>();

public class TestTwoFactorTokenProvider : IUserTwoFactorTokenProvider<RtUser>
{
    public const string ValidTestCode = "123456";

    public Task<bool> ValidateAsync(string purpose, string token,
        UserManager<RtUser> manager, RtUser user)
    {
        return Task.FromResult(token == ValidTestCode);
    }

    public Task<string> GenerateAsync(string purpose,
        UserManager<RtUser> manager, RtUser user)
    {
        return Task.FromResult(ValidTestCode);
    }

    public Task<bool> CanGenerateTwoFactorTokenAsync(
        UserManager<RtUser> manager, RtUser user)
    {
        return Task.FromResult(true);
    }
}
```

**Vorteile:**
- Einfach zu testen (Code ist immer "123456")
- Keine externe Abhängigkeit

**Nachteile:**
- Testet nicht den echten TOTP-Algorithmus
- Muss sorgfältig konfiguriert werden

### 3.3 Gewählter Ansatz: Option C (Kombiniert) ✅

**Unit Tests mit Test Token Provider:**
```csharp
// Schnelle Tests mit festem Code
[Fact]
public async Task TwoFactorLogin_WithTestCode_Succeeds()
{
    // Test Token Provider akzeptiert immer "123456"
    var result = await Login2faAsync("123456");
    result.Success.Should().BeTrue();
}
```

**Integration Tests mit echten TOTP-Codes:**
```csharp
// Realistische E2E Tests
[Fact]
public async Task TwoFactorLogin_WithRealTOTP_Succeeds()
{
    // Echter TOTP-Code wird generiert
    var totp = new Totp(authenticatorKey);
    var code = totp.ComputeTotp();

    var result = await Login2faAsync(code);
    result.Success.Should().BeTrue();
}
```

**Konfiguration in CustomWebApplicationFactory:**
```csharp
// Für Unit Tests: Test Token Provider registrieren
services.Configure<IdentityOptions>(options =>
{
    options.Tokens.AuthenticatorTokenProvider = "TestAuthenticator";
});
services.AddTransient<IUserTwoFactorTokenProvider<RtUser>, TestTwoFactorTokenProvider>();

// Für Integration Tests: Standard Provider verwenden (default)
```

## 4. Getroffene Entscheidungen

### Entscheidung 1: 2FA-Methoden ✅
- [x] **TOTP Authenticator** (Google Authenticator, Microsoft Authenticator, etc.)
- [x] **Email-basierte Codes** (wenn E-Mail-Service konfiguriert)
- [ ] ~~SMS-basierte Codes~~ (nicht in Phase 1)
- [x] **Recovery Codes** (10 Stück, einmal verwendbar)

### Entscheidung 2: "Remember this machine" ✅
- **Ja**, wird implementiert
- 2FA wird für konfigurierbare Zeit (z.B. 30 Tage) auf diesem Gerät übersprungen
- Erfordert zusätzliches Cookie (`2fa_remember`)

### Entscheidung 3: Recovery Codes ✅
- **10 Codes** werden generiert
- **Einmal verwendbar** - nach Verwendung wird der Code invalidiert
- Benutzer kann neue Codes generieren (alle alten werden ungültig)

### Entscheidung 4: Erzwungene 2FA
- **Phase 2** - wird in der zweiten Implementierungsrunde umgesetzt
- Dann: Konfigurierbar pro Rolle (z.B. Admin muss 2FA haben)

### Entscheidung 5: Test-Strategie ✅
- **Option C: Beide Ansätze**
- Unit Tests: Test Token Provider für schnelle, isolierte Tests
- Integration Tests: Echte TOTP-Codes mit `Otp.NET` für E2E-Tests

### Entscheidung 6: Angular UI Design ✅
- **LCARS-Design** für alle 2FA-Komponenten
- **QR-Code mit Octo-Logo** (Meshmakers Logo) in der Mitte
- Verwendet QRCoder mit Logo-Overlay

## 5. Implementierungs-Phasen

### Phase 1.1: Backend API - TOTP Authenticator
1. `GET /api/manage/2fa/status` - 2FA-Status abfragen
2. `POST /api/manage/2fa/authenticator/setup` - QR-Code generieren (mit Octo-Logo)
3. `POST /api/manage/2fa/authenticator/verify` - Code verifizieren & 2FA aktivieren
4. `POST /api/manage/2fa/disable` - 2FA deaktivieren
5. `POST /api/auth/login-2fa` - 2FA-Login mit TOTP-Code
6. `POST /api/auth/login-2fa-email` - 2FA-Login mit Email-Code

### Phase 1.2: Backend API - Recovery & Remember
1. `POST /api/manage/2fa/recovery-codes/generate` - Recovery Codes generieren
2. `POST /api/auth/login-recovery` - Login mit Recovery Code
3. "Remember this machine" Cookie-Handling im 2FA-Login

### Phase 1.3: Angular UI
1. `TwoFactorStatusComponent` - 2FA aktivieren/deaktivieren im Profil
2. `AuthenticatorSetupComponent` - QR-Code mit Octo-Logo anzeigen
3. `TwoFactorLoginComponent` - 2FA-Code eingeben beim Login
4. `RecoveryCodesComponent` - Recovery Codes anzeigen/generieren
5. LCARS-Styling für alle Komponenten

### Phase 1.4: Tests
1. Unit Tests mit Test Token Provider (fester Code "123456")
2. Integration Tests mit echten TOTP-Codes (`Otp.NET`)
3. Tests für Recovery Codes und Remember Machine

### Phase 2: Erweiterungen (spätere Runde)
1. Erzwungene 2FA für bestimmte Rollen
2. Admin-UI zur 2FA-Verwaltung für andere Benutzer
3. 2FA-Audit-Logging

## 6. QR-Code mit Octo-Logo

### Technische Umsetzung

```csharp
// QR-Code mit Logo generieren
using QRCoder;
using System.Drawing;

public byte[] GenerateQrCodeWithLogo(string otpAuthUri, byte[] logoImage)
{
    using var qrGenerator = new QRCodeGenerator();
    var qrCodeData = qrGenerator.CreateQrCode(otpAuthUri, QRCodeGenerator.ECCLevel.H);

    using var qrCode = new QRCode(qrCodeData);

    // Logo in die Mitte einbetten
    using var logo = Image.FromStream(new MemoryStream(logoImage));
    var qrImage = qrCode.GetGraphic(
        pixelsPerModule: 10,
        darkColor: Color.FromArgb(0x07, 0x17, 0x2b),  // Deep Sea (LCARS Background)
        lightColor: Color.White,
        icon: logo,
        iconSizePercent: 15,  // Logo nimmt 15% der QR-Code-Größe ein
        iconBorderWidth: 2
    );

    using var ms = new MemoryStream();
    qrImage.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
    return ms.ToArray();
}
```

### Logo-Anforderungen
- **Format:** PNG mit Transparenz
- **Größe:** Mindestens 100x100 Pixel für gute Qualität
- **Speicherort:** `wwwroot/images/octo-logo.png` oder als Embedded Resource
- **ECC Level H:** Hohe Fehlerkorrektur (30%), ermöglicht Logo in der Mitte

### Angular Darstellung

```html
<!-- LCARS-styled QR Code Display -->
<div class="lcars-panel lcars-panel--accent">
  <div class="lcars-header">Authenticator Setup</div>
  <div class="qr-code-container">
    <img [src]="qrCodeDataUrl" alt="Scan with authenticator app" />
  </div>
  <div class="manual-key">
    <span class="label">Manual Key:</span>
    <code class="lcars-code">{{ sharedKey }}</code>
  </div>
</div>
```

## 7. Abhängigkeiten

| Package | Zweck | Version |
|---------|-------|---------|
| `Otp.NET` | TOTP-Code Generierung für Tests | 1.3.0+ |
| `QRCoder` | QR-Code Generierung mit Logo-Support | 1.4.3+ |
| `System.Drawing.Common` | Bildverarbeitung für QR-Code | 8.0+ |

## 8. Sicherheitsüberlegungen

1. **Authenticator Key Storage:** Der geheime Schlüssel muss sicher gespeichert werden (verschlüsselt)
2. **Rate Limiting:** Schutz gegen Brute-Force auf 2FA-Codes
3. **Recovery Codes:** Sollten nur einmal angezeigt werden, dann gehasht gespeichert
4. **Session Handling:** 2FA-State muss sicher zwischen Login und 2FA-Verification übertragen werden
