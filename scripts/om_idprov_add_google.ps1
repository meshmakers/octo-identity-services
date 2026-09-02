# Add Google Identity Provider
#
# Credentials come from scripts/secrets.local.json (gitignored) — copy
# scripts/secrets.local.json.template and fill in the "google" section.
#
# Prerequisites:
# 1. Create OAuth 2.0 credentials at https://console.cloud.google.com/apis/credentials
#    (application type: Web application)
# 2. Set authorized redirect URI to: https://localhost:5003/signin-google
# 3. Configure OAuth consent screen with scopes: email, profile, openid
#
# Usage:
#   ./om_idprov_add_google.ps1                       # active octo-cli context
#   ./om_idprov_add_google.ps1 -context local_salzburgdev

param (
    [string]$secretsFile = (Join-Path $PSScriptRoot "secrets.local.json"),
    [string]$name = "Google",
    [string]$context
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $secretsFile)) {
    Write-Host "Secrets file '$secretsFile' not found." -ForegroundColor Red
    Write-Host "Copy scripts/secrets.local.json.template to scripts/secrets.local.json and fill in the values." -ForegroundColor Yellow
    exit 1
}

$secrets = Get-Content $secretsFile -Raw | ConvertFrom-Json
if (-not $secrets.google -or
    [string]::IsNullOrWhiteSpace($secrets.google.clientId) -or
    [string]::IsNullOrWhiteSpace($secrets.google.clientSecret)) {
    Write-Host "Missing 'google.clientId' / 'google.clientSecret' in $secretsFile" -ForegroundColor Red
    exit 1
}

$contextArgs = @()
if ($context) { $contextArgs = @("--context", $context) }

octo-cli @contextArgs -c AddOAuthIdentityProvider -n $name -e true -t google `
    --clientId $secrets.google.clientId --clientSecret $secrets.google.clientSecret
exit $LASTEXITCODE
