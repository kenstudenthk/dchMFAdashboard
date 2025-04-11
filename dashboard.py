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
            with st.spinner("Initializing authentication..."):
                # Get token using client credentials
                result = auth.get_token_on_behalf_of()
                
                if result and 'access_token' in result:
                    st.session_state.token = result['access_token']
                    st.session_state.authenticated = True
                    st.success("✅ Successfully authenticated!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Authentication failed. Please try again.")
                    if result and 'error' in result:
                        st.error(f"Error: {result['error']}")
    
    except Exception as e:
        st.error("Authentication Error")
        st.error(f"Details: {str(e)}")

def render_report():
    """Render the main report interface"""
    st.title("📊 MFA Status Report")
    
    # Sidebar filters
    st.sidebar.title("Filters")
    
    try:
        # Initialize Graph API
        graph_api = GraphAPI(st.session_state.token)
        
        # Add a container for the main content
        main_container = st.container()
        
        with main_container:
            # Data loading button with progress
            if st.button("🔄 Load User Data", use_container_width=True):
                with st.spinner("Loading user data..."):
                    df = graph_api.get_users_report()
                    st.session_state.data = df
                    st.success("✅ Data loaded successfully!")
        
            # Show data if available
            if st.session_state.data is not None:
                df = st.session_state.data
                
                # Filters in sidebar
                with st.sidebar:
                    st.markdown("### Data Filters")
                    mfa_filter = st.checkbox("Show only MFA disabled users")
                    license_filter = st.multiselect(
                        "Filter by License",
                        options=['Office365 E1', 'Office365 E3', 'EMS E3', 'EMS E5']
                    )
                
                # Apply filters
                if mfa_filter:
                    df = df[~df['MFA Enabled']]
                if license_filter:
                    df = df[df['Licenses'].str.contains('|'.join(license_filter))]
                
                # Metrics
                st.markdown("### Overview Metrics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Users", len(df))
                with col2:
                    st.metric("MFA Disabled", len(df[~df['MFA Enabled']]))
                with col3:
                    st.metric("Active Users", len(df[df['Last Interactive SignIn'] != '']))
                
                # Data display
                st.markdown("### User Data")
                st.dataframe(
                    df,
                    hide_index=True,
                    column_config={
                        "MFA Enabled": st.column_config.CheckboxColumn(
                            "MFA Status",
                            help="Multi-Factor Authentication Status"
                        )
                    }
                )
                
                # Export options
                st.markdown("### Export Options")
                if st.button("📥 Export to CSV", use_container_width=True):
                    csv = df.to_csv(index=False)
                    st.download_button(
                        label="💾 Download CSV File",
                        data=csv,
                        file_name=f"mfa_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
    
    except Exception as e:
        st.error("Error in rendering report")
        st.error(f"Details: {str(e)}")

def main():
    try:
        # Initialize session state
        init_session_state()
        
        # Add sidebar logo and info
        with st.sidebar:
            st.markdown("## MFA Status Report")
            st.markdown("---")
        
        # Check authentication and render appropriate view
        if not check_auth():
            render_login()
        else:
            render_report()
            
            # Add logout button to sidebar
            with st.sidebar:
                if st.button("🚪 Logout", use_container_width=True):
                    for key in st.session_state.keys():
                        del st.session_state[key]
                    st.rerun()
        
        # Add footer
        st.markdown("---")
        st.markdown(
            """
            <div style='text-align: center'>
                <p>MFA Status Report • Built with Streamlit</p>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    except Exception as e:
        st.error("Application Error")
        st.error(f"Details: {str(e)}")

if __name__ == "__main__":
    main()