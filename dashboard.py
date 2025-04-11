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
    st.title("🔐 MFA Status Report")
    st.markdown("### Microsoft Authentication Required")

    if 'auth_flow' not in st.session_state:
        st.session_state.auth_flow = None

    try:
        auth = init_auth()

        # Initialize authentication
        if st.button("Begin Authentication", use_container_width=True):
            with st.spinner("Initializing authentication..."):
                flow = auth.get_device_flow()
                if flow and "user_code" in flow:
                    st.session_state.auth_flow = flow
                    st.rerun()
                else:
                    st.error("Failed to initialize authentication. Please try again.")

        # Display authentication instructions
        if st.session_state.auth_flow:
            flow = st.session_state.auth_flow
            
            st.markdown("### Authentication Instructions")
            
            col1, col2 = st.columns([2,1])
            
            with col1:
                # Display the verification URI
                st.markdown("1. **Visit this website:**")
                st.code(flow.get('verification_uri', ''), language=None)
                
                # Display the user code
                st.markdown("2. **Enter this code:**")
                st.code(flow.get('user_code', ''), language=None)
                
                st.markdown("3. **Complete the sign-in process in your browser**")
            
            with col2:
                # Process authentication
                with st.spinner("Waiting for authentication..."):
                    result = auth.process_device_flow(flow)
                    
                    if result and 'access_token' in result:
                        st.session_state.token = result['access_token']
                        st.session_state.authenticated = True
                        st.success("✅ Authentication successful!")
                        st.session_state.auth_flow = None
                        time.sleep(1)
                        st.rerun()
            
            # Cancel button
            if st.button("Cancel Authentication", type="secondary"):
                st.session_state.auth_flow = None
                st.rerun()

    except Exception as e:
        st.error("Authentication Error")
        st.error(f"Details: {str(e)}")
        st.session_state.auth_flow = None
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