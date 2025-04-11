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
    st.markdown("### Microsoft Authentication Required")
    
    try:
        auth = init_auth()
        
        if st.button("Sign in with Microsoft Account", use_container_width=True):
            with st.spinner("Initializing authentication..."):
                result = auth.acquire_token_interactive()
                
                if result and 'access_token' in result:
                    st.session_state.token = result['access_token']
                    st.session_state.authenticated = True
                    st.success("✅ Successfully authenticated!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Authentication failed. Please try again.")
                    if result and 'error' in result:
                        st.error(f"Error: {result.get('error_description', 'Unknown error')}")
    
    except Exception as e:
        st.error("Authentication Error")
        st.error(f"Details: {str(e)}")

def render_report():
    """Render the main report interface"""
    st.title("📊 MFA Status Report")
    
    try:
        # Initialize Graph API
        graph_api = GraphAPI(st.session_state.token)
        
        # Add load data button
        if st.button("Load User Data"):
            with st.spinner("Loading user data..."):
                df = graph_api.get_users_report()
                st.session_state.data = df
        
        # Show data if available
        if st.session_state.data is not None:
            df = st.session_state.data
            
            # Add filters
            mfa_filter = st.checkbox("Show only MFA disabled users")
            if mfa_filter:
                df = df[~df['MFA Enabled']]
            
            # Display data
            st.dataframe(df)
            
            # Export button
            if st.button("Export to CSV"):
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"mfa_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
    
    except Exception as e:
        st.error("Error in rendering report")
        st.error(f"Details: {str(e)}")

def main():
    """Main function to run the Streamlit app"""
    try:
        # Initialize session state
        init_session_state()
        
        # Check authentication and render appropriate view
        if not check_auth():
            render_login()
        else:
            render_report()
            
            # Add logout button
            if st.sidebar.button("Logout"):
                for key in st.session_state.keys():
                    del st.session_state[key]
                st.rerun()
    
    except Exception as e:
        st.error("Application Error")
        st.error(f"Details: {str(e)}")

if __name__ == "__main__":
    main()