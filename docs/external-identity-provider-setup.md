# External Identity Provider Setup Guide

This document provides step-by-step instructions for configuring external identity providers with Octo Identity Services.

## Table of Contents

- [Microsoft Account](#microsoft-account)
- [Google](#google)
- [Facebook](#facebook)
- [Azure Entra ID](#azure-entra-id)
- [Troubleshooting](#troubleshooting)

---

## Microsoft Account

Microsoft Account authentication allows users to sign in with their personal Microsoft accounts (Outlook.com, Hotmail.com, Live.com) or organizational accounts (Microsoft 365, Azure AD).

### Prerequisites

- Azure subscription (free tier works)
- Access to [Azure Portal](https://portal.azure.com/)

### Step 1: Create App Registration

1. Navigate to [Azure Portal](https://portal.azure.com/)
2. Search for **"App registrations"** in the search bar
3. Click **"+ New registration"**

### Step 2: Configure Application Settings

| Field | Value |
|-------|-------|
| **Name** | Choose a descriptive name (e.g., "OctoMesh Identity") |
| **Supported account types** | **"Accounts in any organizational directory and personal Microsoft accounts"** |
| **Redirect URI** | Platform: **Web**, URI: `https://localhost:5003/signin-microsoft` |

> **IMPORTANT:** The "Supported account types" selection is critical. Choose the option that matches your authentication needs:
>
> | Option | Use Case |
> |--------|----------|
> | Personal Microsoft accounts only | Consumer apps only (Outlook, Hotmail, Live) |
> | Accounts in any organizational directory and personal Microsoft accounts | **Recommended** - Both consumer and business accounts |
> | Accounts in this organizational directory only | Enterprise apps restricted to one tenant |
> | Accounts in any organizational directory | Multi-tenant enterprise apps without consumer accounts |

4. Click **"Register"**

### Step 3: Note the Application (Client) ID

After registration, you'll be redirected to the app overview page.

1. Copy the **Application (client) ID** - you'll need this later
2. This is a GUID like: `a1970774-ad6e-457e-83eb-b9d5d52c7583`

### Step 4: Create Client Secret

1. In the left menu, click **"Certificates & secrets"**
2. Under "Client secrets", click **"+ New client secret"**
3. Add a description (e.g., "OctoMesh Development")
4. Select an expiration period (6 months, 12 months, 24 months, or custom)
5. Click **"Add"**
6. **IMMEDIATELY copy the secret value** - it will only be shown once!

> **WARNING:** The secret value is only displayed once. If you lose it, you must create a new secret.

### Step 5: Add Identity Provider to OctoMesh

Use the `octo-cli` tool to register the identity provider:

```bash
octo-cli -c AddOAuthIdentityProvider \
  -n "Microsoft" \
  -e true \
  --clientId "YOUR_CLIENT_ID" \
  --clientSecret "YOUR_CLIENT_SECRET" \
  -t microsoft
```

Or use the provided PowerShell script (after editing with your credentials):

```powershell
# scripts/om_idprov_add_microsoft.ps1
octo-cli -c AddOAuthIdentityProvider -n "Microsoft" -e true --clientId "YOUR_CLIENT_ID" --clientSecret "YOUR_CLIENT_SECRET" -t microsoft
```

### Step 6: Configure Redirect URIs for Production

For production environments, add the appropriate redirect URI:

1. Go back to **"Authentication"** in the left menu
2. Under "Platform configurations" > "Web", click **"Add URI"**
3. Add your production URI: `https://your-domain.com/signin-microsoft`

### Microsoft Account Parameters

| Parameter | Description |
|-----------|-------------|
| `-n` / `--name` | Display name shown on login button |
| `-e` / `--enabled` | Enable the provider (true/false) |
| `--clientId` | Application (client) ID from Azure Portal |
| `--clientSecret` | Client secret value |
| `-t` / `--type` | Provider type: `microsoft` |

---

## Google

Google authentication allows users to sign in with their Google accounts.

### Prerequisites

- Google account
- Access to [Google Cloud Console](https://console.cloud.google.com/)

### Step 1: Create Google Cloud Project

1. Navigate to [Google Cloud Console](https://console.cloud.google.com/)
2. Click the project dropdown and select **"New Project"**
3. Enter a project name and click **"Create"**

### Step 2: Configure OAuth Consent Screen

1. In the left menu, go to **"APIs & Services"** > **"OAuth consent screen"**
2. Select User Type:
   - **External**: For apps available to any Google user
   - **Internal**: For apps restricted to your Google Workspace organization
3. Fill in the required fields:
   - App name
   - User support email
   - Developer contact information
4. Click **"Save and Continue"**
5. Add scopes: `email`, `profile`, `openid`
6. Click **"Save and Continue"**

### Step 3: Create OAuth Credentials

1. Go to **"APIs & Services"** > **"Credentials"**
2. Click **"+ Create Credentials"** > **"OAuth client ID"**
3. Select Application type: **Web application**
4. Add a name
5. Under "Authorized redirect URIs", add:
   - `https://localhost:5003/signin-google` (development)
   - `https://your-domain.com/signin-google` (production)
6. Click **"Create"**
7. Copy the **Client ID** and **Client Secret**

### Step 4: Add Identity Provider to OctoMesh

```bash
octo-cli -c AddOAuthIdentityProvider \
  -n "Google" \
  -e true \
  --clientId "YOUR_CLIENT_ID.apps.googleusercontent.com" \
  --clientSecret "YOUR_CLIENT_SECRET" \
  -t google
```

---

## Facebook

Facebook authentication allows users to sign in with their Facebook accounts.

### Prerequisites

- Facebook account
- Access to [Facebook Developers](https://developers.facebook.com/)

### Step 1: Create Facebook App

1. Navigate to [Facebook Developers](https://developers.facebook.com/)
2. Click **"My Apps"** > **"Create App"**
3. Select app type: **"Consumer"** or **"Business"**
4. Enter app details and click **"Create App"**

### Step 2: Configure Facebook Login

1. In the App Dashboard, go to **"Add Products"**
2. Find **"Facebook Login"** and click **"Set Up"**
3. Select **"Web"** as the platform
4. Enter your site URL

### Step 3: Configure OAuth Settings

1. Go to **"Facebook Login"** > **"Settings"**
2. Under "Valid OAuth Redirect URIs", add:
   - `https://localhost:5003/signin-facebook` (development)
   - `https://your-domain.com/signin-facebook` (production)
3. Click **"Save Changes"**

### Step 4: Get App Credentials

1. Go to **"Settings"** > **"Basic"**
2. Copy the **App ID** and **App Secret**

### Step 5: Add Identity Provider to OctoMesh

```bash
octo-cli -c AddOAuthIdentityProvider \
  -n "Facebook" \
  -e true \
  --clientId "YOUR_APP_ID" \
  --clientSecret "YOUR_APP_SECRET" \
  -t facebook
```

---

## Azure Entra ID

Azure Entra ID (formerly Azure Active Directory) provides enterprise authentication for organizational accounts.

### Prerequisites

- Azure subscription
- Azure Entra ID tenant
- Access to [Azure Portal](https://portal.azure.com/)

### Step 1: Create App Registration

1. Navigate to [Azure Portal](https://portal.azure.com/)
2. Go to **"Microsoft Entra ID"** > **"App registrations"**
3. Click **"+ New registration"**

### Step 2: Configure Application Settings

| Field | Value |
|-------|-------|
| **Name** | Choose a descriptive name |
| **Supported account types** | Select based on your needs (single tenant or multi-tenant) |
| **Redirect URI** | Platform: **Web**, URI: `https://localhost:5003/signin-oidc` |

4. Click **"Register"**

### Step 3: Note the IDs

From the app overview page, copy:
- **Application (client) ID**
- **Directory (tenant) ID**

### Step 4: Create Client Secret

1. Click **"Certificates & secrets"**
2. Under "Client secrets", click **"+ New client secret"**
3. Add description and select expiration
4. Click **"Add"** and copy the secret value

### Step 5: Configure Token Claims (Optional)

To include group claims:
1. Go to **"Token configuration"**
2. Click **"+ Add groups claim"**
3. Select the group types to include
4. Click **"Add"**

### Step 6: Add Identity Provider to OctoMesh

```bash
octo-cli -c AddOAuthIdentityProvider \
  -n "Azure AD" \
  -e true \
  --clientId "YOUR_CLIENT_ID" \
  --clientSecret "YOUR_CLIENT_SECRET" \
  --tenantId "YOUR_TENANT_ID" \
  -t azuread
```

---

## Troubleshooting

### Common Errors

#### Microsoft Account: "userAudience" Error

**Error Message:**
```
The 'userAudience' configuration of this application must not be configured with 'Consumer' as the user audience. You need to create a separate app registration for 'Consumer' audience scenarios.
```

**Cause:** The app registration is configured for "Personal Microsoft accounts only" but the authentication is trying to use organizational features.

**Solution:**
1. Create a new app registration
2. Select **"Accounts in any organizational directory and personal Microsoft accounts"**
3. Use the new Client ID and Secret

#### Microsoft Account: "unauthorized_client" Error

**Error Message:**
```
AADSTS700016: Application with identifier 'xxx' was not found in the directory
```

**Cause:** The Client ID is incorrect or the app registration was deleted.

**Solution:**
1. Verify the Client ID matches the Azure Portal
2. Ensure the app registration exists
3. Check you're using the correct Azure tenant

#### Google: "redirect_uri_mismatch" Error

**Cause:** The redirect URI in the request doesn't match any URI configured in Google Cloud Console.

**Solution:**
1. Go to Google Cloud Console > Credentials
2. Add the exact redirect URI: `https://localhost:5003/signin-google`
3. Ensure protocol (http/https) and port match exactly

#### Facebook: "URL Blocked" Error

**Cause:** The redirect URI is not in the allowed list.

**Solution:**
1. Go to Facebook App Settings > Facebook Login > Settings
2. Add the redirect URI to "Valid OAuth Redirect URIs"
3. Make sure the app is in Live mode (not Development)

### Redirect URI Reference

| Provider | Redirect URI Path |
|----------|-------------------|
| Microsoft Account | `/signin-microsoft` |
| Google | `/signin-google` |
| Facebook | `/signin-facebook` |
| Azure Entra ID | `/signin-oidc` |

**Full URL Format:** `https://{your-domain}/{signin-path}`

**Development:** `https://localhost:5003/{signin-path}`

### Debug Tips

1. **Check Browser Console:** Look for JavaScript errors or failed network requests
2. **Check Server Logs:** Identity Services logs authentication events
3. **Verify Credentials:** Double-check Client ID and Secret are correct
4. **Test Redirect URI:** Ensure the URI is accessible and matches configuration
5. **Check Provider Status:** Some providers have status pages for outages

---

## Scripts Reference

Setup scripts are located in `/scripts/`:

| Script | Description |
|--------|-------------|
| `om_idprov_add_google.ps1` | Add Google identity provider |
| `om_idprov_add_microsoft.ps1` | Add Microsoft Account identity provider |

Edit these scripts with your credentials before running.
