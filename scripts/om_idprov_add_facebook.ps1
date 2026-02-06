# Add Facebook Identity Provider
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
# Usage: Replace APP_ID and APP_SECRET with your values

octo-cli -c AddOAuthIdentityProvider -n "Facebook" -e true --clientId "1427275525510370" --clientSecret "677fb281cb36903afc56a0679fe94cb2" -t facebook
