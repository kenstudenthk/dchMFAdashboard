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

def render_login():
    """Render login interface"""
    st.title("🔐 MFA Status Report")
    st.markdown("Please login to continue")
    
    auth = init_auth()
    
    if st.button("Login with Microsoft"):
        flow = auth.initiate_device_flow()
        st.code(flow['message'])
        
        with st.spinner('Waiting for authentication...'):
            result = auth.acquire_token_by_device_flow(flow)
            if result:
                st.session_state.token = result['access_token']
                st.session_state.authenticated = True
                st.success("Successfully logged in!")
                time.sleep(1)
                st.rerun()

def render_report():
    """Render the main report interface"""
    st.title("📊 MFA Status Report")
    
    # Sidebar filters
    st.sidebar.title("Filters")
    
    # Initialize Graph API
    graph_api = GraphAPI(st.session_state.token)
    
    # Data loading
    if st.button("Load Data"):
        with st.spinner("Loading user data..."):
            df = graph_api.get_users_report()
            st.session_state.data = df
    
    # Show data if available
    if st.session_state.data is not None:
        df = st.session_state.data
        
        # Filters
        mfa_filter = st.sidebar.checkbox("Show only MFA disabled")
        license_filter = st.sidebar.multiselect(
            "Filter by License",
            options=['Office365 E1', 'Office365 E3', 'EMS E3', 'EMS E5']
        )
        
        # Apply filters
        if mfa_filter:
            df = df[~df['MFA Enabled']]
        if license_filter:
            df = df[df['Licenses'].str.contains('|'.join(license_filter))]
        
        # Show metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Users", len(df))
        with col2:
            st.metric("MFA Disabled", len(df[~df['MFA Enabled']]))
        with col3:
            st.metric("Active Users", len(df[df['Last Interactive SignIn'] != '']))
        
        # Show data
        st.dataframe(df)
        
        # Export buttons
        if st.button("Export to CSV"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"mfa_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

def main():
    init_session_state()
    
    if not st.session_state.authenticated:
        render_login()
    else:
        render_report()

if __name__ == "__main__":
    main()