# auth.py
import streamlit as st
import requests
from datetime import datetime, timedelta
import time

class GraphPermissionError(Exception):
    """Custom exception for Graph API permission errors"""
    def __init__(self, endpoint: str, status_code: int, error_data: dict):
        self.endpoint = endpoint
        self.status_code = status_code
        self.error_data = error_data
        super().__init__(self.get_error_message())
    
    def get_error_message(self):
        if self.error_data.get('error', {}).get('message'):
            return self.error_data['error']['message']
        return f"Access denied to {self.endpoint}"

def make_graph_request(endpoint: str, token: str) -> dict:
    """Make a request to Microsoft Graph API with error handling"""
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'ConsistencyLevel': 'eventual'
        }
        
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
            
        error_data = response.json() if response.text else {}
        
        if response.status_code in [401, 403]:
            st.error("🔑 Access Denied - Please check permissions and try again")
            logout(show_message=False)
            st.stop()
        elif response.status_code == 404:
            st.error(f"❌ Resource not found: {endpoint}")
        elif response.status_code == 429:
            st.warning("⚠️ Too many requests. Please wait a moment and try again.")
            retry_after = int(response.headers.get('Retry-After', 30))
            time.sleep(retry_after)
            return make_graph_request(endpoint, token)
        else:
            st.error(f"API Error ({response.status_code}): {error_data.get('error', {}).get('message')}")
            
        raise GraphPermissionError(endpoint, response.status_code, error_data)
        
    except requests.exceptions.Timeout:
        st.error("⚠️ Request timed out. Please try again.")
    except requests.exceptions.RequestException as e:
        st.error(f"Network error: {str(e)}")
    except Exception as e:
        st.error(f"Error: {str(e)}")
    
    return None

def check_auth() -> bool:
    """Check if user is authenticated and token is not expired"""
    if not st.session_state.get('token'):
        return False
        
    if st.session_state.get('token_timestamp'):
        token_age = datetime.now() - st.session_state.token_timestamp
        if token_age > timedelta(hours=1):
            st.warning("🔄 Token has expired. Please login again.")
            logout(show_message=False)
            return False
            
    return True

def verify_token(token: str) -> bool:
    """Verify if the token is valid"""
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers=headers
        )
        return response.status_code == 200
    except:
        return False

def render_login():
    """Render the login page"""
    st.title("🔐 MFA Status Report")
    
    st.markdown("""
    ### Get Your Access Token:
    1. Go to [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
    2. Sign in with your Microsoft account
    3. Click your profile icon
    4. Select "Access Token"
    5. Copy the token and paste below
    """)
    
    with st.form("token_form"):
        token = st.text_input("Access Token:", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted and token:
            if verify_token(token):
                st.session_state.token = token
                st.session_state.token_timestamp = datetime.now()
                st.success("✅ Authentication successful!")
                st.rerun()
            else:
                st.error("❌ Invalid token. Please try again.")

def logout(show_message: bool = True):
    """Clear the session state to logout"""
    st.session_state.clear()
    if show_message:
        st.success("👋 Logged out successfully!")
    st.rerun()