# save_state.py

# Azure AD Configuration
CLIENT_ID = "b3eee569-7d4b-4976-9af4-9f683063448f"
TENANT_ID = "common"

# Required Microsoft Graph API Scopes
SCOPES = [
    'User.Read',
    'User.Read.All',
    'Directory.Read.All',
    'UserAuthenticationMethod.Read.All',
    'AuditLog.Read.All',
    'offline_access'  # Add this for refresh tokens
]

# Graph API endpoint
ENDPOINT = "https://graph.microsoft.com/v1.0"