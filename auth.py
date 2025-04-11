# auth.py
import msal
import streamlit as st
from save_state import CLIENT_ID, CLIENT_SECRET, TENANT_ID, SCOPES

class GraphAuth:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.client_secret = CLIENT_SECRET
        self.tenant_id = TENANT_ID
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        
        self.app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority
        )

    def get_auth_url(self):
        """Get authorization URL"""
        auth_url = self.app.get_authorization_request_url(
            scopes=SCOPES,
            redirect_uri="http://localhost:8501/",  # Streamlit default port
            state=st.session_state.get("state", "state123")
        )
        return auth_url

    def acquire_token_by_auth_code(self, auth_code):
        """Acquire token using authorization code"""
        result = self.app.acquire_token_by_authorization_code(
            code=auth_code,
            scopes=SCOPES,
            redirect_uri="http://localhost:8501/"
        )
        return result

    def acquire_token_silent(self):
        """Try to acquire token silently"""
        accounts = self.app.get_accounts()
        if accounts:
            result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
            return result
        return None

    def get_token_on_behalf_of(self):
        """Get access token using client credentials flow"""
        result = self.app.acquire_token_for_client(scopes=SCOPES)
        return result

def init_auth():
    """Initialize authentication"""
    return GraphAuth()

def check_auth():
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)