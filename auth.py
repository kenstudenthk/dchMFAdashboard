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

    def get_device_flow(self):
        """Initialize device code flow"""
        try:
            flow = self.app.initiate_device_flow(scopes=SCOPES)
            if "user_code" not in flow:
                raise ValueError("Failed to create device flow")
            return flow
        except Exception as e:
            st.error(f"Error creating device flow: {str(e)}")
            return None

    def acquire_token_by_device_flow(self, flow):
        """Acquire token using device code flow"""
        try:
            result = self.app.acquire_token_by_device_flow(flow)
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