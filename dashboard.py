# dashboard.py
import streamlit as st
import pandas as pd
from datetime import datetime
import time
from auth import make_graph_request, check_auth, render_login, logout

# Streamlit config
st.set_page_config(
    page_title="MFA Status Report",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

def load_mfa_data():
    """Load MFA status data from Graph API"""
    try:
        users_endpoint = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled"
        users_data = make_graph_request(users_endpoint, st.session_state.token)
        
        if not users_data:
            return None
            
        users = users_data.get('value', [])
        
        mfa_data = []
        with st.progress(0) as progress:
            for i, user in enumerate(users):
                auth_methods_endpoint = f"https://graph.microsoft.com/v1.0/users/{user['id']}/authentication/methods"
                auth_methods = make_graph_request(auth_methods_endpoint, st.session_state.token)
                
                if auth_methods:
                    methods = auth_methods.get('value', [])
                    mfa_data.append({
                        'Display Name': user['displayName'],
                        'Email': user['userPrincipalName'],
                        'Account Enabled': user['accountEnabled'],
                        'MFA Methods': [m.get('method', '') for m in methods],
                        'MFA Enabled': len(methods) > 0
                    })
                
                progress.progress((i + 1) / len(users))
                
        return pd.DataFrame(mfa_data)
        
    except Exception as e:
        st.error(f"Error loading MFA data: {str(e)}")
        return None

def main():
    if not check_auth():
        render_login()
    else:
        st.title("🔐 MFA Status Report")
        
        # Sidebar
        with st.sidebar:
            if st.button("Refresh Data"):
                st.session_state.data = None
                st.rerun()
            
            if st.button("Logout"):
                logout()
        
        # Load data if needed
        if 'data' not in st.session_state or st.session_state.data is None:
            with st.spinner("Loading MFA data..."):
                st.session_state.data = load_mfa_data()
        
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
            st.dataframe(df)

if __name__ == "__main__":
    main()