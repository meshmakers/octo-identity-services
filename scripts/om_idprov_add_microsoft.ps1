# Add Microsoft Account Identity Provider
#
# Credentials come from scripts/secrets.local.json (gitignored) — copy
# scripts/secrets.local.json.template and fill in the "microsoft" section.
#
# Prerequisites:
# 1. Register app at https://portal.azure.com/ -> App registrations
# 2. IMPORTANT: Supported account types must be "Accounts in any organizational directory and personal Microsoft accounts"
#    Do NOT use "Personal Microsoft accounts only" - this causes "userAudience" errors!
# 3. Set redirect URI to: Platform: Web, URI: https://localhost:5003/signin-microsoft
# 4. Create a client secret under "Certificates & secrets" and copy the value immediately
#
# See docs/external-identity-provider-setup.md for detailed setup instructions
#
# Usage:
#   ./om_idprov_add_microsoft.ps1                       # active octo-cli context
#   ./om_idprov_add_microsoft.ps1 -context local_salzburgdev

param (
    [string]$secretsFile = (Join-Path $PSScriptRoot "secrets.local.json"),
    [string]$name = "Microsoft",
    [string]$context
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $secretsFile)) {
    Write-Host "Secrets file '$secretsFile' not found." -ForegroundColor Red
    Write-Host "Copy scripts/secrets.local.json.template to scripts/secrets.local.json and fill in the values." -ForegroundColor Yellow
    exit 1
}

$secrets = Get-Content $secretsFile -Raw | ConvertFrom-Json
if (-not $secrets.microsoft -or
    [string]::IsNullOrWhiteSpace($secrets.microsoft.clientId) -or
    [string]::IsNullOrWhiteSpace($secrets.microsoft.clientSecret)) {
    Write-Host "Missing 'microsoft.clientId' / 'microsoft.clientSecret' in $secretsFile" -ForegroundColor Red
    exit 1
}

$contextArgs = @()
if ($context) { $contextArgs = @("--context", $context) }

octo-cli @contextArgs -c AddOAuthIdentityProvider -n $name -e true -t microsoft `
    --clientId $secrets.microsoft.clientId --clientSecret $secrets.microsoft.clientSecret
exit $LASTEXITCODE
