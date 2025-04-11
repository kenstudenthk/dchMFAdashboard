# save_state.py

import os
from typing import List

# Azure AD Configuration
CLIENT_ID = "b3eee569-7d4b-4976-9af4-9f683063448f"
TENANT_ID = "0c354a30-f421-4d42-bd98-0d86e396d207"

# Required Microsoft Graph API Scopes as a list
SCOPES = [
    'User.Read',
    'User.Read.All',
    'Directory.Read.All',
    'UserAuthenticationMethod.Read.All',
    'AuditLog.Read.All'
]

# Graph API endpoint
ENDPOINT = "https://graph.microsoft.com/v1.0"
