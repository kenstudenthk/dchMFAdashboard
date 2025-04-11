# save_state.py
import streamlit as st
import os
from typing import List

# save_state.py
GRAPH_TOKEN = "YOUR_ACCESS_TOKEN"  # Token from Graph Explorer
ENDPOINT = "https://graph.microsoft.com/v1.0"

# Simple auth check
def check_auth():
    return bool(st.session_state.get('token'))

# Simple login page
def render_login():
    st.title("🔐 MFA Status Report")
    st.markdown("### Authentication Required")
    
    with st.form("token_form"):
        token = st.text_input("Enter your Microsoft Graph access token:", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted and token:
            st.session_state.token = token
            st.success("Authentication successful!")
            st.rerun()
