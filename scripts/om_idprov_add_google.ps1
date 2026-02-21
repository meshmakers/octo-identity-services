# Add Google Identity Provider
#
# Prerequisites:
# 1. Create OAuth 2.0 credentials at https://console.cloud.google.com/apis/credentials
# 2. Set redirect URI to: https://localhost:5003/signin-google
# 3. Configure OAuth consent screen with scopes: email, profile, openid
#
# Usage: Replace CLIENT_ID and CLIENT_SECRET with your values

octo-cli -c AddOAuthIdentityProvider -n "Google" -e true --clientId "979172155722-6i62lnkitdgcfen0c1m0bgmh02jpne4p.apps.googleusercontent.com" --clientSecret "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" -t google
