# config.py
import os
from typing import List

# Azure AD Configuration
CLIENT_ID = "b3eee569-7d4b-4976-9af4-9f683063448f"
CLIENT_SECRET = "oVL8Q~5Xe4y~86pIBYPBOUi7swmIsRpnj75aAcGy"
TENANT_ID = "0c354a30-f421-4d42-bd98-0d86e396d207"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

# Redirect URI for authentication
REDIRECT_URI = "http://localhost:8501"  # Streamlit default port

# Required Microsoft Graph API Scopes
SCOPES = [
    'User.Read',
    'User.Read.All',
    'Directory.Read.All',
    'UserAuthenticationMethod.Read.All',
    'AuditLog.Read.All'
]

# Graph API endpoint
ENDPOINT = "https://graph.microsoft.com/v1.0"