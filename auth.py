# auth.py
import streamlit as st
import requests
from datetime import datetime, timedelta

def check_auth() -> bool:
    """Check if user is authenticated and token is not expired"""
    if 'token' not in st.session_state:
        return False
        
    if not st.session_state.token:
        return False
        
    # Check token expiration if we have timestamp
    if 'token_timestamp' in st.session_state:
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
    1. Open [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
    2. Sign in with your Microsoft account
    3. Click your profile icon in the top right
    4. Select "Access Token"
    5. Copy the token and paste below
    """)
    
    token = st.text_input("Access Token:", type="password")
    if st.button("Login"):
        if not token:
            st.error("⚠️ Please enter a token")
        elif verify_token(token):
            # Store token and timestamp
            st.session_state.token = token
            st.session_state.token_timestamp = datetime.now()
            st.success("✅ Authentication successful!")
            # Don't use rerun here
        else:
            st.error("❌ Invalid token. Please try again.")

    st.markdown("""
    #### Token Tips:
    - Tokens expire after 1 hour
    - If you get errors, get a new token from Graph Explorer
    - Make sure you're signed in with your work/school account
    """)

def logout(show_message: bool = True):
    """Clear the session state to logout"""
    st.session_state.clear()
    if show_message:
        st.success("👋 Logged out successfully!")