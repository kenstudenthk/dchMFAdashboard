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

    def initiate_device_flow(self):
        """Initiate the device code flow for authentication"""
        flow = self.app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            raise ValueError("Failed to create device flow")
        return flow

    def acquire_token_by_device_flow(self, flow):
        """Complete the device code flow and acquire token"""
        result = self.app.acquire_token_by_device_flow(flow)
        return result

    def acquire_token_silent(self):
        """Try to acquire token silently"""
        accounts = self.app.get_accounts()
        if accounts:
            result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
            return result
        return None

def init_auth():
    """Initialize authentication"""
    return GraphAuth()

def check_auth():
    """Check if user is authenticated"""
    if 'token' not in st.session_state:
        return False
    return True