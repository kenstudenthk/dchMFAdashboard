# auth.py
import msal
import streamlit as st
from save_state import CLIENT_ID, TENANT_ID, SCOPES, REDIRECT_URI

class GraphAuth:
    def __init__(self):
        self.client_id = CLIENT_ID
        
        self.authority = f"https://login.microsoftonline.com/{TENANT_ID}"
        
        self.app = msal.PublicClientApplication(
            client_id=self.client_id,
            authority=self.authority
        )

    def get_auth_url(self):
        """Generate authorization URL for interactive login"""
        try:
            auth_url = self.app.get_authorization_request_url(
                scopes=SCOPES,
                redirect_uri=REDIRECT_URI,
                state=st.session_state.get("state", "12345")
            )
            return auth_url
        except Exception as e:
            st.error(f"Error creating authorization URL: {str(e)}")
            return None

    def acquire_token_interactive(self):
        """Acquire token using interactive login"""
        try:
            accounts = self.app.get_accounts()
            if accounts:
                # If account exists, try to acquire token silently
                result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
            else:
                # If no account exists, start interactive login
                result = self.app.acquire_token_interactive(
                    scopes=SCOPES,
                    redirect_uri=REDIRECT_URI
                )
            return result
        except Exception as e:
            st.error(f"Error acquiring token: {str(e)}")
            return None

def init_auth():
    """Initialize authentication"""
    return GraphAuth()

def check_auth():
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)