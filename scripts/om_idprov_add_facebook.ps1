# Add Facebook Identity Provider
#
# Credentials come from scripts/secrets.local.json (gitignored) — copy
# scripts/secrets.local.json.template and fill in the "facebook" section.
#
# Prerequisites:
# 1. Register as Facebook Developer at https://developers.facebook.com/
# 2. Create app at https://developers.facebook.com/apps/create/
#    - Select app type: "Consumer" or "Business"
# 3. Add "Facebook Login" product to your app
# 4. Go to Facebook Login > Settings and add Valid OAuth Redirect URI:
#    https://localhost:5003/signin-facebook
# 5. Get App ID and App Secret from Settings > Basic
#
# IMPORTANT: For production, the app must be in "Live" mode (not "Development")
#
# See docs/external-identity-provider-setup.md for detailed setup instructions
#
# Usage:
#   ./om_idprov_add_facebook.ps1                       # active octo-cli context
#   ./om_idprov_add_facebook.ps1 -context local_salzburgdev

param (
    [string]$secretsFile = (Join-Path $PSScriptRoot "secrets.local.json"),
    [string]$name = "Facebook",
    [string]$context
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $secretsFile)) {
    Write-Host "Secrets file '$secretsFile' not found." -ForegroundColor Red
    Write-Host "Copy scripts/secrets.local.json.template to scripts/secrets.local.json and fill in the values." -ForegroundColor Yellow
    exit 1
}

$secrets = Get-Content $secretsFile -Raw | ConvertFrom-Json
if (-not $secrets.facebook -or
    [string]::IsNullOrWhiteSpace($secrets.facebook.appId) -or
    [string]::IsNullOrWhiteSpace($secrets.facebook.appSecret)) {
    Write-Host "Missing 'facebook.appId' / 'facebook.appSecret' in $secretsFile" -ForegroundColor Red
    exit 1
}

$contextArgs = @()
if ($context) { $contextArgs = @("--context", $context) }

octo-cli @contextArgs -c AddOAuthIdentityProvider -n $name -e true -t facebook `
    --clientId $secrets.facebook.appId --clientSecret $secrets.facebook.appSecret
exit $LASTEXITCODE
