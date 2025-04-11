# save_state.py

import os
from typing import List

# Azure AD Configuration
CLIENT_ID = "b3eee569-7d4b-4976-9af4-9f683063448f"
TENANT_ID = "organizations"

# Required Microsoft Graph API Scopes as a list
SCOPES = [
    'https://graph.microsoft.com/AuditLog.Read.All',
    'https://graph.microsoft.com/Directory.Read.All',
    'https://graph.microsoft.com/User.Read',
    'https://graph.microsoft.com/User.Read.All',
    'https://graph.microsoft.com/UserAuthenticationMethod.Read.All'
]

# Graph API endpoint
ENDPOINT = "https://graph.microsoft.com/v1.0"