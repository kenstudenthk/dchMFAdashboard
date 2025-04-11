# auth.py
import streamlit as st
import requests
from datetime import datetime, timedelta
import json

class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    pass

def check_auth() -> bool:
    """
    Check if user is authenticated and token is not expired
    Returns: bool indicating if user is authenticated with valid token
    """
    if not st.session_state.get('token'):
        return False
        
    # Check token expiration if we have timestamp
    if st.session_state.get('token_timestamp'):
        token_age = datetime.now() - st.session_state.token_timestamp
        if token_age > timedelta(hours=1):
            st.warning("🔄 Token has expired. Please login again.")
            logout(show_message=False)
            return False
            
    return True

def verify_token(token: str) -> bool:
    """
    Verify if the token is valid by making test API calls
    Args:
        token: The access token to verify
    Returns: bool indicating if token is valid
    """
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Test basic profile access
        me_response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers=headers
        )
        
        # Test directory access
        users_response = requests.get(
            'https://graph.microsoft.com/v1.0/users?$top=1',
            headers=headers
        )
        
        if me_response.status_code != 200:
            st.error("❌ Token lacks basic profile permissions")
            return False
            
        if users_response.status_code != 200:
            st.error("❌ Token lacks directory access permissions")
            return False
            
        return True
        
    except requests.exceptions.RequestException as e:
        st.error(f"Network error: {str(e)}")
        return False
    except Exception as e:
        st.error(f"Verification error: {str(e)}")
        return False

def render_login():
    """Render the login page with token input and instructions"""
    st.title("🔐 MFA Status Report")
    
    # Instructions
    st.markdown("""
    ### Get Your Access Token:
    1. Open [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
    2. Sign in with your Microsoft account
    3. Click your profile icon in the top right
    4. Select "Access Token"
    5. Copy the token and paste below
    
    #### Required Permissions:
    - User.Read
    - User.Read.All
    - Directory.Read.All
    - UserAuthenticationMethod.Read.All
    - AuditLog.Read.All
    """)
    
    # Login form
    with st.form("token_form"):
        token = st.text_input("Access Token:", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            if not token:
                st.error("⚠️ Please enter a token")
            elif verify_token(token):
                # Store token and timestamp
                st.session_state.token = token
                st.session_state.token_timestamp = datetime.now()
                
                # Store user info
                try:
                    headers = {'Authorization': f'Bearer {token}'}
                    response = requests.get(
                        'https://graph.microsoft.com/v1.0/me',
                        headers=headers
                    )
                    user_info = response.json()
                    st.session_state.user_name = user_info.get('displayName')
                    st.session_state.user_email = user_info.get('userPrincipalName')
                except:
                    pass
                    
                st.success("✅ Authentication successful!")
                st.rerun()
            else:
                st.error("❌ Invalid token. Please check permissions and try again.")

    # Help text
    with st.expander("ℹ️ Token Help"):
        st.markdown("""
        #### Token Tips:
        - Tokens expire after 1 hour
        - If you get errors, get a new token from Graph Explorer
        - Make sure you're signed in with your work/school account
        - Check that all required permissions are granted
        
        #### Common Issues:
        1. **Token Expired**: Get a new token from Graph Explorer
        2. **Missing Permissions**: Make sure to consent to all required permissions
        3. **Wrong Account**: Use your work/school account, not personal
        """)

def logout(show_message: bool = True):
    """
    Clear the session state to logout
    Args:
        show_message: Whether to show logout message
    """
    st.session_state.clear()
    if show_message:
        st.success("👋 Logged out successfully!")
    st.rerun()

def render_user_info():
    """Render current user information in sidebar"""
    if check_auth() and st.session_state.get('user_name'):
        with st.sidebar:
            st.write("---")
            st.write("👤 Logged in as:")
            st.write(f"**{st.session_state.user_name}**")
            if st.session_state.get('user_email'):
                st.write(f"_{st.session_state.user_email}_")
            
            # Show token expiration countdown
            if st.session_state.get('token_timestamp'):
                expires_in = timedelta(hours=1) - (datetime.now() - st.session_state.token_timestamp)
                if expires_in > timedelta(0):
                    st.write(f"⏳ Token expires in: {int(expires_in.total_seconds() / 60)} minutes")
                
            if st.button("🚪 Logout"):
                logout()

def init_auth():
    """Initialize authentication state"""
    if 'token' not in st.session_state:
        st.session_state.token = None
    if 'token_timestamp' not in st.session_state:
        st.session_state.token_timestamp = None