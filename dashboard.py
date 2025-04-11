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
        if not users:
            st.warning("No users found in the directory.")
            return None
            
        total_users = len(users)
        mfa_data = []
        
        progress_text = "Loading user data..."
        progress_bar = st.progress(0, text=progress_text)
        
        for i, user in enumerate(users):
            try:
                auth_methods_endpoint = f"https://graph.microsoft.com/v1.0/users/{user['id']}/authentication/methods"
                auth_methods = make_graph_request(auth_methods_endpoint, st.session_state.token)
                
                if auth_methods is None:
                    continue
                    
                methods = []
                has_mfa = False
                
                if 'value' in auth_methods:
                    methods = [m.get('method', '') for m in auth_methods['value']]
                    has_mfa = any(m for m in methods if m not in ['password', ''])
                
                mfa_data.append({
                    'DisplayName': user['displayName'],
                    'Email': user['userPrincipalName'],
                    'AccountEnabled': user['accountEnabled'],
                    'MFAEnabled': has_mfa,
                    'AuthMethods': ', '.join(m for m in methods if m)
                })
                
                # Update progress
                progress = (i + 1) / total_users
                progress_bar.progress(progress, text=f"{progress_text} ({i + 1}/{total_users})")
                
            except Exception as e:
                st.error(f"Error processing user {user['displayName']}: {str(e)}")
        
        if not mfa_data:
            st.warning("No user data could be loaded.")
            return None
            
        return pd.DataFrame(mfa_data)
        
    except Exception as e:
        st.error(f"Error loading MFA data: {str(e)}")
        return None

def render_dashboard(df):
    """Render the dashboard with MFA data"""
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    total_users = len(df)
    active_users = len(df[df['AccountEnabled'] == True])
    mfa_enabled = len(df[df['MFAEnabled'] == True])
    mfa_percentage = (mfa_enabled / active_users * 100) if active_users > 0 else 0
    
    with col1:
        st.metric("Total Users", total_users)
    with col2:
        st.metric("Active Users", active_users)
    with col3:
        st.metric("MFA Enabled", mfa_enabled)
    with col4:
        st.metric("MFA Adoption", f"{mfa_percentage:.1f}%")
    
    # Filters
    st.subheader("Filters")
    col1, col2 = st.columns(2)
    
    with col1:
        show_active = st.checkbox("Show Active Accounts", value=True)
        show_inactive = st.checkbox("Show Inactive Accounts", value=False)
    with col2:
        show_mfa = st.checkbox("Show MFA Enabled", value=True)
        show_no_mfa = st.checkbox("Show MFA Disabled", value=True)
    
    # Apply filters
    mask = pd.Series(False, index=df.index)
    
    if show_active:
        mask |= df['AccountEnabled'] == True
    if show_inactive:
        mask |= df['AccountEnabled'] == False
    if show_mfa:
        mask &= df['MFAEnabled'] == True
    if show_no_mfa:
        mask |= df['MFAEnabled'] == False
    
    filtered_df = df[mask].copy()
    
    # Format display data
    filtered_df['AccountStatus'] = filtered_df['AccountEnabled'].map({True: 'Active', False: 'Disabled'})
    filtered_df['MFAStatus'] = filtered_df['MFAEnabled'].map({True: 'Enabled', False: 'Disabled'})
    
    # Display table
    st.subheader("User Details")
    st.dataframe(
        filtered_df[[
            'DisplayName',
            'Email',
            'AccountStatus',
            'MFAStatus',
            'AuthMethods'
        ]],
        hide_index=True,
        column_config={
            'DisplayName': st.column_config.TextColumn('Display Name'),
            'Email': st.column_config.TextColumn('Email'),
            'AccountStatus': st.column_config.TextColumn('Account Status'),
            'MFAStatus': st.column_config.TextColumn('MFA Status'),
            'AuthMethods': st.column_config.TextColumn('Authentication Methods')
        }
    )
    
    # Last refresh time
    st.caption(f"Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    # Initialize session state
    if 'token' not in st.session_state:
        st.session_state.token = None
    
    if not check_auth():
        render_login()
        # Check if we just logged in
        if st.session_state.token:
            st.rerun()
    else:
        st.title("🔐 MFA Status Report")
        
        # Sidebar
        with st.sidebar:
            if st.button("🔄 Refresh Data"):
                st.session_state.data = None
                st.rerun()
            
            if st.button("🚪 Logout"):
                logout()
        
        # Load data
        if 'data' not in st.session_state or st.session_state.data is None:
            with st.spinner("Loading MFA data..."):
                st.session_state.data = load_mfa_data()
        
        # Render dashboard
        if st.session_state.data is not None:
            render_dashboard(st.session_state.data)

if __name__ == "__main__":
    main()