# Add Google Identity Provider
#
# Prerequisites:
# 1. Create OAuth 2.0 credentials at https://console.cloud.google.com/apis/credentials
# 2. Set redirect URI to: https://localhost:5003/signin-google
# 3. Configure OAuth consent screen with scopes: email, profile, openid
#
# Usage: Replace CLIENT_ID and CLIENT_SECRET with your values

octo-cli -c AddOAuthIdentityProvider -n "Google" -e true --clientId "***REMOVED-GOOGLE-CLIENTID-AB3837***" --clientSecret "***REMOVED-GOOGLE-SECRET-AB3837***" -t google
