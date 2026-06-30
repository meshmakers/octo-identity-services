# Add Azure Entra ID Identity Provider
#
# Prerequisites:
# 1. Register app at https://portal.azure.com/ -> App registrations
# 2. Set redirect URI to: Platform: Web, URI: https://localhost:5003/signin-azure-entra-id
# 3. Create a client secret under "Certificates & secrets" and copy the value immediately
# 4. Note your directory (tenant) ID, application (client) ID, and client secret value
#
# See docs/external-identity-provider-setup.md for detailed setup instructions
#
# Usage: Replace TENANT_ID, CLIENT_ID and CLIENT_SECRET with your values
#        (or export them as environment variables and reference $env:NAME below)

octo-cli -c AddAzureEntryIdIdentityProvider -n "meshmakers" -e true --tenantId "YOUR_TENANT_ID" --clientId "YOUR_CLIENT_ID" --clientSecret "YOUR_CLIENT_SECRET"
