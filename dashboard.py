# app.py
import streamlit as st
import pandas as pd
from datetime import datetime
import time
from auth import GraphAuth, init_auth, check_auth
from mfa_status import GraphAPI

# Streamlit config
st.set_page_config(
    page_title="MFA Status Report",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

def init_session_state():
    """Initialize session state variables"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'token' not in st.session_state:
        st.session_state.token = None
    if 'data' not in st.session_state:
        st.session_state.data = None

def check_auth():
    return bool(st.session_state.get('token'))

def render_login():
    st.title("🔐 MFA Status Report")
    
    st.markdown("""
    ### Get Your Access Token:
    1. Go to [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
    2. Sign in with your Microsoft account
    3. Click your profile icon
    4. Select "Access Token"
    5. Copy the token and paste below
    """)
    
    with st.form("token_form"):
        token = st.text_input("Access Token:", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted and token:
            # Verify token by making a test API call
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(
                'https://graph.microsoft.com/v1.0/me',
                headers=headers
            )
            
            if response.status_code == 200:
                st.session_state.token = token
                st.success("✅ Authentication successful!")
                st.rerun()
            else:
                st.error("❌ Invalid token. Please try again.")

def main():
    if not check_auth():
        render_login()
    else:
        st.title("🔐 MFA Status Report")
        st.success("You are logged in!")
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()

if __name__ == "__main__":
    main()