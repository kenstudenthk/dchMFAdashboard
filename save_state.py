# save_state.py
ENDPOINT = "https://graph.microsoft.com/v1.0"

# Required Microsoft Graph API endpoints
ENDPOINTS = {
    'users': f"{ENDPOINT}/users",
    'me': f"{ENDPOINT}/me",
    'authMethods': f"{ENDPOINT}/reports/authenticationMethods"
}