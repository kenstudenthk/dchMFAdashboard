# auth.py
import streamlit as st
import requests
from datetime import datetime, timedelta
import json

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

def verify_permissions(token: str) -> tuple[bool, list]:
    """
    Verify all required Graph API permissions
    Returns: (success, missing_permissions)
    """
    headers = {'Authorization': f'Bearer {token}'}
    permission_checks = [
    {
        'endpoint': 'https://graph.microsoft.com/v1.0/me',
        'permission': 'User.Read',
        'description': 'Read your profile'
    },
    {
        'endpoint': 'https://graph.microsoft.com/v1.0/users',
        'permission': 'User.Read.All',
        'description': "Read all users' profiles"  # Using double quotes here
    },
    {
        'endpoint': 'https://graph.microsoft.com/v1.0/reports/authenticationMethods',
        'permission': 'Reports.Read.All',
        'description': 'Read authentication methods'
    },
    {
        'endpoint': 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName',
        'permission': 'Directory.Read.All',
        'description': 'Read directory data'
    }
]
    
    missing_permissions = []
    
    for check in permission_checks:
        try:
            response = requests.get(check['endpoint'], headers=headers)
            if response.status_code in [401, 403]:
                missing_permissions.append(check)
        except Exception:
            missing_permissions.append(check)
    
    return len(missing_permissions) == 0, missing_permissions

def verify_token(token: str) -> bool:
    """Verify if the token is valid and has required permissions"""
    try:
        has_permissions, missing = verify_permissions(token)
        
        if not has_permissions:
            st.error("❌ Token lacks required permissions:")
            for perm in missing:
                st.error(f"- {perm['permission']}: {perm['description']}")
            
            st.markdown("""
            ### How to Fix Permission Issues:
            1. Go to [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
            2. Click your profile icon → "Select permissions"
            3. Search for and enable these permissions:
                - User.Read
                - User.Read.All
                - Directory.Read.All
                - Reports.Read.All
            4. Click "Consent"
            5. Get a new token
            """)
            return False
            
        return True
        
    except Exception as e:
        st.error(f"Verification error: {str(e)}")
        return False

def make_graph_request(endpoint: str, token: str) -> dict:
    """
    Make a request to Microsoft Graph API with error handling
    """
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'ConsistencyLevel': 'eventual'  # Add this for better performance
        }
        
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=30  # Add timeout
        )
        
        if response.status_code == 200:
            return response.json()
            
        error_data = response.json()
        
        if response.status_code in [401, 403]:
            # Token expired or permission issues
            st.error("🔑 Access Denied - Please check permissions and try again")
            logout(show_message=False)
            st.stop()
            
        elif response.status_code == 404:
            st.error(f"❌ Resource not found: {endpoint}")
            
        elif response.status_code == 429:
            # Rate limiting
            st.warning("⚠️ Too many requests. Please wait a moment and try again.")
            retry_after = int(response.headers.get('Retry-After', 30))
            time.sleep(retry_after)
            return make_graph_request(endpoint, token)  # Retry
            
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

def render_login():
    """Render the login page"""
    st.title("🔐 MFA Status Report")
    
    with st.expander("📋 Required Permissions", expanded=True):
        st.markdown("""
        This app requires the following Microsoft Graph permissions:
        - **User.Read**: Read your basic profile
        - **User.Read.All**: Read all users' profiles
        - **Directory.Read.All**: Read directory data
        - **Reports.Read.All**: Read authentication method reports
        
        To grant these permissions:
        1. Go to [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
        2. Sign in with your work account
        3. Click your profile picture → "Select permissions"
        4. Search for and enable each permission above
        5. Click "Consent" to approve
        6. Get a new token
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

    with st.expander("🔍 Troubleshooting"):
        st.markdown("""
        Common Error Solutions:
        1. **Access Denied**: Make sure you've granted all required permissions
        2. **Token Expired**: Get a new token (tokens expire after 1 hour)
        3. **Wrong Account**: Use your work/school account, not personal
        4. **Admin Consent**: Some permissions may need admin approval
        """)