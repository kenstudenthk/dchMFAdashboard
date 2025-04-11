# auth.py
import msal
import streamlit as st
from save_state import CLIENT_ID, TENANT_ID, SCOPES

class GraphAuth:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.authority = f"https://login.microsoftonline.com/{TENANT_ID}"
        
        self.app = msal.PublicClientApplication(
            client_id=self.client_id,
            authority=self.authority
        )

    def get_token(self):
        """Get access token using interactive browser login"""
        try:
            # Check for existing accounts
            accounts = self.app.get_accounts()
            if accounts:
                # If account exists, try silent token acquisition
                result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
                if result:
                    return result
            
            # If no silent token available, do interactive login
            result = self.app.acquire_token_interactive(
                scopes=SCOPES,
                prompt="select_account"  # Force account selection
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