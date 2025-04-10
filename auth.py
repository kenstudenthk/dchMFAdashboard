import msal
import streamlit as st
import requests
import traceback
from typing import Optional, Dict, Any

# Azure AD app registration details
APP_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
SCOPES = [
    "User.Read",
    "Directory.Read.All",
    "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All"
]

class GraphAuth:
    def __init__(self):
        """Initialize the GraphAuth class with MSAL configuration"""
        try:
            # Initialize token cache
            cache = msal.SerializableTokenCache()
            
            # Load existing cache if available
            if 'token_cache' in st.session_state:
                cache.deserialize(st.session_state['token_cache'])
                
            # Initialize MSAL application
            self.app = msal.PublicClientApplication(
                APP_ID,
                authority="https://login.microsoftonline.com/common",
                token_cache=cache
            )
            
            # Save cache if state changed
            if cache.has_state_changed:
                st.session_state['token_cache'] = cache.serialize()
                
        except Exception as e:
            st.error(f"MSAL initialization error: {str(e)}")
            st.code(traceback.format_exc())

    def get_token(self) -> Optional[str]:
        """Get the access token from cache or new authentication"""
        try:
            accounts = self.app.get_accounts()
            if accounts:
                # If account exists, try to get token silently
                result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
                if result:
                    return result['access_token']
            return None
        except Exception as e:
            st.error(f"Token acquisition error: {str(e)}")
            return None

    def get_token_from_cache(self) -> Optional[str]:
        """Attempt to get token from cache only"""
        try:
            accounts = self.app.get_accounts()
            if accounts:
                result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
                if result:
                    return result['access_token']
            return None
        except Exception as e:
            st.error(f"Cache token error: {str(e)}")
            return None

    def initiate_device_flow(self) -> Optional[Dict[str, Any]]:
        """Initiate the device code flow authentication"""
        try:
            flow = self.app.initiate_device_flow(scopes=SCOPES)
            if 'user_code' not in flow:
                st.error('Failed to create device flow')
                return None
            return flow
        except Exception as e:
            st.error(f"Device flow error: {str(e)}")
            return None

    def acquire_token_by_device_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Complete the device code flow authentication"""
        try:
            return self.app.acquire_token_by_device_flow(flow)
        except Exception as e:
            st.error(f"Token acquisition error: {str(e)}")
            return None

    def logout(self) -> bool:
        """Remove all accounts and clear cache"""
        try:
            accounts = self.app.get_accounts()
            for account in accounts:
                self.app.remove_account(account)
            if 'token_cache' in st.session_state:
                del st.session_state['token_cache']
            return True
        except Exception as e:
            st.error(f"Logout error: {str(e)}")
            return False

    def check_token_validity(self, token: str) -> bool:
        """Check if the token is still valid"""
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(
                'https://graph.microsoft.com/v1.0/me',
                headers=headers
            )
            return response.status_code == 200
        except Exception as e:
            st.error(f"Token validation error: {str(e)}")
            return False

    def refresh_token(self) -> Optional[str]:
        """Attempt to refresh the access token"""
        try:
            accounts = self.app.get_accounts()
            if accounts:
                result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
                if result:
                    return result['access_token']
            return None
        except Exception as e:
            st.error(f"Token refresh error: {str(e)}")
            return None

def init_auth() -> GraphAuth:
    """Initialize authentication if not already done"""
    if 'auth' not in st.session_state:
        st.session_state.auth = GraphAuth()
    return st.session_state.auth

def get_auth_token() -> Optional[str]:
    """Get the current authentication token"""
    auth = init_auth()
    return auth.get_token_from_cache()

def check_auth() -> bool:
    """Check if user is authenticated"""
    token = get_auth_token()
    if token:
        auth = init_auth()
        return auth.check_token_validity(token)
    return False