# Add Azure Entra ID Identity Provider
#
# Credentials come from scripts/secrets.local.json (gitignored) — copy
# scripts/secrets.local.json.template and fill in the "entra" section.
#
# Prerequisites:
# 1. Register app at https://portal.azure.com/ -> App registrations
# 2. Set redirect URI to: Platform: Web, URI: https://localhost:5003/auth/signin-callback
#    (the callback path is set by AzureEntraIdAuthSchemeCreator)
# 3. Create a client secret under "Certificates & secrets" and copy the value immediately
# 4. Note your directory (tenant) ID, application (client) ID, and client secret value
#
# See docs/external-identity-provider-setup.md for detailed setup instructions
#
# Usage:
#   ./om_idprov_add_entra.ps1                       # active octo-cli context
#   ./om_idprov_add_entra.ps1 -context local_salzburgdev

param (
    [string]$secretsFile = (Join-Path $PSScriptRoot "secrets.local.json"),
    [string]$name = "meshmakers",
    [string]$context
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $secretsFile)) {
    Write-Host "Secrets file '$secretsFile' not found." -ForegroundColor Red
    Write-Host "Copy scripts/secrets.local.json.template to scripts/secrets.local.json and fill in the values." -ForegroundColor Yellow
    exit 1
}

$secrets = Get-Content $secretsFile -Raw | ConvertFrom-Json
if (-not $secrets.entra -or
    [string]::IsNullOrWhiteSpace($secrets.entra.tenantId) -or
    [string]::IsNullOrWhiteSpace($secrets.entra.clientId) -or
    [string]::IsNullOrWhiteSpace($secrets.entra.clientSecret)) {
    Write-Host "Missing 'entra.tenantId' / 'entra.clientId' / 'entra.clientSecret' in $secretsFile" -ForegroundColor Red
    exit 1
}

$contextArgs = @()
if ($context) { $contextArgs = @("--context", $context) }

octo-cli @contextArgs -c AddAzureEntryIdIdentityProvider -n $name -e true `
    --tenantId $secrets.entra.tenantId `
    --clientId $secrets.entra.clientId --clientSecret $secrets.entra.clientSecret
exit $LASTEXITCODE
