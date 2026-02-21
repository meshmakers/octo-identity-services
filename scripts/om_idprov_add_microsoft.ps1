# Add Microsoft Account Identity Provider
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
# Usage: Replace CLIENT_ID and CLIENT_SECRET with your values

octo-cli -c AddOAuthIdentityProvider -n "Microsoft" -e true --clientId "YOUR_CLIENT_ID" --clientSecret "YOUR_CLIENT_SECRET" -t microsoft
