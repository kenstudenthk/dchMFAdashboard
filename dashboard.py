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
        # Get users with specific properties
        users_endpoint = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled"
        users_data = make_graph_request(users_endpoint, st.session_state.token)
        
        if not users_data:
            return None
            
        users = users_data.get('value', [])
        
        # Get authentication methods for each user
        mfa_data = []
        total_users = len(users)
        
        with st.progress(0) as progress:
            for i, user in enumerate(users):
                try:
                    auth_methods_endpoint = f"https://graph.microsoft.com/v1.0/users/{user['id']}/authentication/methods"
                    auth_methods = make_graph_request(auth_methods_endpoint, st.session_state.token)
                    
                    methods = []
                    has_mfa = False
                    
                    if auth_methods and 'value' in auth_methods:
                        methods = [m.get('method', '') for m in auth_methods['value']]
                        # Consider MFA enabled if there's more than just a password
                        has_mfa = any(m for m in methods if m not in ['password', ''])
                    
                    mfa_data.append({
                        'Display Name': user['displayName'],
                        'Email': user['userPrincipalName'],
                        'Account Status': 'Active' if user['accountEnabled'] else 'Disabled',
                        'MFA Status': 'Enabled' if has_mfa else 'Disabled',
                        'Authentication Methods': ', '.join(m for m in methods if m),
                        'Has MFA': has_mfa  # Boolean column for calculations
                    })
                except Exception as e:
                    st.error(f"Error processing user {user['displayName']}: {str(e)}")
                
                progress.progress((i + 1) / total_users)
        
        # Convert to DataFrame
        df = pd.DataFrame(mfa_data)
        
        # Sort by Display Name
        df = df.sort_values('Display Name')
        
        return df
        
    except Exception as e:
        st.error(f"Error loading MFA data: {str(e)}")
        return None

def render_dashboard(df):
    """Render the dashboard with MFA data"""
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_users = len(df)
        st.metric("Total Users", total_users)
    
    with col2:
        active_users = len(df[df['Account Status'] == 'Active'])
        st.metric("Active Users", active_users)
    
    with col3:
        mfa_enabled = df['Has MFA'].sum()
        st.metric("MFA Enabled", int(mfa_enabled))
    
    with col4:
        mfa_percentage = (mfa_enabled / active_users * 100) if active_users > 0 else 0
        st.metric("MFA Adoption", f"{mfa_percentage:.1f}%")
    
    # Data table
    st.subheader("User Details")
    
    # Filter controls
    col1, col2 = st.columns(2)
    with col1:
        status_filter = st.multiselect(
            "Account Status",
            options=['Active', 'Disabled'],
            default=['Active']
        )
    with col2:
        mfa_filter = st.multiselect(
            "MFA Status",
            options=['Enabled', 'Disabled'],
            default=['Enabled', 'Disabled']
        )
    
    # Apply filters
    filtered_df = df[
        (df['Account Status'].isin(status_filter)) &
        (df['MFA Status'].isin(mfa_filter))
    ]
    
    # Display filtered data
    st.dataframe(
        filtered_df.drop('Has MFA', axis=1),  # Hide the boolean column
        hide_index=True,
        column_config={
            'Display Name': st.column_config.TextColumn('Display Name'),
            'Email': st.column_config.TextColumn('Email'),
            'Account Status': st.column_config.TextColumn('Account Status'),
            'MFA Status': st.column_config.TextColumn('MFA Status'),
            'Authentication Methods': st.column_config.TextColumn('Authentication Methods')
        }
    )
    
    # Show last refresh time
    st.caption(f"Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    if not check_auth():
        render_login()
    else:
        st.title("🔐 MFA Status Report")
        
        # Sidebar
        with st.sidebar:
            if st.button("🔄 Refresh Data"):
                st.session_state.data = None
                st.rerun()
            
            if st.button("🚪 Logout"):
                logout()
        
        # Load or refresh data
        if 'data' not in st.session_state or st.session_state.data is None:
            with st.spinner("Loading MFA data..."):
                st.session_state.data = load_mfa_data()
        
        # Render dashboard if data is available
        if st.session_state.data is not None:
            render_dashboard(st.session_state.data)

if __name__ == "__main__":
    main()