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
    defaults = {
        'authenticated': False,
        'token': None,
        'data': None,
        'state': None,
        'processing': False,
        'error': None
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

def render_login():
    """Render login interface"""
    st.title("🔐 MFA Status Report")
    st.markdown("### Authentication Required")
    
    try:
        auth = init_auth()
        
        if st.button("Login with Microsoft", use_container_width=True):
            with st.spinner("Authenticating..."):
                result = auth.get_token()
                
                if result and 'access_token' in result:
                    st.session_state.token = result['access_token']
                    st.session_state.authenticated = True
                    st.success("✅ Successfully authenticated!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Authentication failed. Please check your credentials.")
    
    except Exception as e:
        st.error("Authentication Error")
        st.error(f"Details: {str(e)}")

if __name__ == "__main__":
    main()