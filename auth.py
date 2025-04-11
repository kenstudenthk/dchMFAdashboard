# auth.py
import msal
import streamlit as st
from save_state import CLIENT_ID, CLIENT_SECRET, TENANT_ID, AUTHORITY, SCOPES

class GraphAuth:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.client_secret = CLIENT_SECRET
        self.authority = AUTHORITY
        
        self.app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority
        )

    def get_token(self):
        """Get access token using client credentials flow"""
        try:
            result = self.app.acquire_token_for_client(scopes=SCOPES)
            if "access_token" in result:
                return result
            else:
                st.error(f"Error acquiring token: {result.get('error_description', 'Unknown error')}")
                return None
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
            return None

def init_auth():
    """Initialize authentication"""
    return GraphAuth()

def check_auth():
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)