# save_state.py

# Azure AD Configuration
CLIENT_ID = "b3eee569-7d4b-4976-9af4-9f683063448f"
TENANT_ID = "common"

# Required Microsoft Graph API Scopes - simplified and essential scopes
SCOPES = [
    'https://graph.microsoft.com/User.Read',
    'https://graph.microsoft.com/User.Read.All',
    'https://graph.microsoft.com/Directory.Read.All',
    'https://graph.microsoft.com/UserAuthenticationMethod.Read.All',
    'https://graph.microsoft.com/AuditLog.Read.All'
]

# Graph API endpoint
ENDPOINT = "https://graph.microsoft.com/v1.0"