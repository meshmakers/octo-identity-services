param(
    [Parameter()] [string]$configuration = "Release"
)

# Start Angular dev server for Identity Services
$clientAppPath = Join-Path -Path $PSScriptRoot -ChildPath "src/IdentityServices/ClientApp"

Write-Host "Starting Identity Services Angular dev server from $clientAppPath" -ForegroundColor Green

Set-Location $clientAppPath
npm start
