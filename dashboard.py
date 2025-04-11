# dashboard.py
import streamlit as st
import pandas as pd
import requests
from datetime import datetime
import time

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
        'token': None,
        'data': None,
        'last_refresh': None,
        'selected_view': 'Summary',
        'filter_query': '',
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

def get_graph_data(endpoint: str) -> dict:
    """Make a request to Microsoft Graph API"""
    headers = {'Authorization': f'Bearer {st.session_state.token}'}
    response = requests.get(
        f'https://graph.microsoft.com/v1.0/{endpoint}',
        headers=headers
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        st.error(f"API Error: {response.status_code} - {response.text}")
        return None

def load_mfa_data():
    """Load MFA status data from Graph API"""
    try:
        # Get all users
        users_data = get_graph_data('users?$select=id,displayName,userPrincipalName,accountEnabled')
        if not users_data:
            return None
            
        users = users_data.get('value', [])
        
        # Get authentication methods for each user
        mfa_data = []
        for user in users:
            auth_methods = get_graph_data(f"users/{user['id']}/authentication/methods")
            if auth_methods:
                methods = auth_methods.get('value', [])
                mfa_data.append({
                    'Display Name': user['displayName'],
                    'Email': user['userPrincipalName'],
                    'Account Enabled': user['accountEnabled'],
                    'MFA Methods': [m.get('method', '') for m in methods],
                    'MFA Enabled': len(methods) > 0
                })
                
        return pd.DataFrame(mfa_data)
        
    except Exception as e:
        st.error(f"Error loading MFA data: {str(e)}")
        return None

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
            # Verify token
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

def render_dashboard():
    st.title("🔐 MFA Status Report")
    
    # Sidebar
    with st.sidebar:
        st.header("Controls")
        if st.button("Refresh Data"):
            st.session_state.data = None
            st.rerun()
            
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()
    
    # Load data if needed
    if st.session_state.data is None:
        with st.spinner("Loading MFA data..."):
            st.session_state.data = load_mfa_data()
            st.session_state.last_refresh = datetime.now()
    
    if st.session_state.data is not None:
        df = st.session_state.data
        
        # Summary metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Users", len(df))
        with col2:
            mfa_enabled = df['MFA Enabled'].sum()
            st.metric("MFA Enabled", mfa_enabled)
        with col3:
            mfa_percentage = (mfa_enabled / len(df)) * 100
            st.metric("MFA Adoption", f"{mfa_percentage:.1f}%")
        
        # Data table
        st.subheader("User Details")
        st.dataframe(
            df,
            hide_index=True,
            column_config={
                'Display Name': st.column_config.TextColumn('Display Name'),
                'Email': st.column_config.TextColumn('Email'),
                'Account Enabled': st.column_config.CheckboxColumn('Active'),
                'MFA Enabled': st.column_config.CheckboxColumn('MFA'),
                'MFA Methods': st.column_config.ListColumn('Methods')
            }
        )
        
        # Last refresh time
        st.caption(f"Last refreshed: {st.session_state.last_refresh.strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    init_session_state()
    
    if not st.session_state.token:
        render_login()
    else:
        render_dashboard()

if __name__ == "__main__":
    main()