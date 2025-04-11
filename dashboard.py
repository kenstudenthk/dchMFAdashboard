# dashboard.py

import streamlit as st
import requests
import time
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
from collections import Counter

# Authentication Functions
def make_graph_request(endpoint: str, token: str) -> dict:
    """Make a request to Microsoft Graph API with error handling"""
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'ConsistencyLevel': 'eventual'
        }
        
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
            
        error_data = response.json() if response.text else {}
        error_message = error_data.get('error', {}).get('message', '')
        
        if response.status_code in [401, 403]:
            st.error("🔑 Access Denied - Please check permissions and try again")
            st.session_state.token = None
            return None
        else:
            st.error(f"API Error ({response.status_code}): {error_message}")
            
        return None
        
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

def check_auth() -> bool:
    """Check if user is authenticated"""
    return 'token' in st.session_state and st.session_state.token is not None

def logout():
    """Clear the session state"""
    st.session_state.clear()
    st.success("👋 Logged out successfully!")

def get_device_code():
    """Get device code for authentication"""
    try:
        payload = {
            'client_id': 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',
            'scope': 'https://graph.microsoft.com/User.Read.All https://graph.microsoft.com/UserAuthenticationMethod.Read.All'
        }
        
        response = requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            data=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Error getting device code: {response.text}")
        return None
            
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

def poll_for_token(device_code):
    """Poll for token using device code"""
    payload = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id': 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',
        'device_code': device_code
    }
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    max_attempts = 60  # 5 minutes maximum
    for attempt in range(max_attempts):
        try:
            response = requests.post(
                'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                data=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                progress_bar.empty()
                status_text.empty()
                return response.json()
                
            progress = (attempt + 1) / max_attempts
            progress_bar.progress(progress)
            status_text.text(f"Waiting for authentication... {attempt + 1}/{max_attempts}")
            
            time.sleep(5)
            
        except Exception as e:
            st.error(f"Error: {str(e)}")
            return None
    
    return None

# Dashboard Functions
def load_mfa_data():
    """Load MFA status data"""
    try:
        users_endpoint = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled"
        users_data = make_graph_request(users_endpoint, st.session_state.token)
        
        if not users_data:
            return None
            
        users = users_data.get('value', [])
        mfa_data = []
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i, user in enumerate(users):
            auth_methods_endpoint = f"https://graph.microsoft.com/v1.0/users/{user['id']}/authentication/methods"
            auth_methods = make_graph_request(auth_methods_endpoint, st.session_state.token)
            
            if auth_methods:
                methods = [m.get('method', '') for m in auth_methods.get('value', [])]
                has_mfa = any(m for m in methods if m not in ['password', ''])
                
                mfa_data.append({
                    'DisplayName': user['displayName'],
                    'Email': user['userPrincipalName'],
                    'AccountEnabled': user['accountEnabled'],
                    'MFAEnabled': has_mfa,
                    'AuthMethods': ', '.join(m for m in methods if m)
                })
            
            progress = (i + 1) / len(users)
            progress_bar.progress(progress)
            status_text.text(f"Loading user data... {i + 1}/{len(users)}")
        
        progress_bar.empty()
        status_text.empty()
        
        return pd.DataFrame(mfa_data)
        
    except Exception as e:
        st.error(f"Error loading MFA data: {str(e)}")
        return None

def render_login():
    """Render login page"""
    st.title("🔐 MFA Status Report")
    
    if st.button("Sign In with Microsoft"):
        device_code_response = get_device_code()
        
        if device_code_response:
            st.markdown(f"""
            ### Please follow these steps:
            1. Go to: https://microsoft.com/devicelogin
            2. Enter code: `{device_code_response['user_code']}`
            3. Complete the sign-in process
            """)
            
            token_response = poll_for_token(device_code_response['device_code'])
            
            if token_response and 'access_token' in token_response:
                st.session_state.token = token_response['access_token']
                st.session_state.token_timestamp = datetime.now()
                st.success("✅ Authentication successful!")
                st.rerun()

def render_dashboard(df):
    """Render dashboard with MFA data"""
    st.title("📊 MFA Status Dashboard")
    
    if st.button("🔄 Refresh Data"):
        st.rerun()
    
    if st.button("🚪 Logout"):
        logout()
        st.rerun()
    
    total_users = len(df)
    mfa_enabled = df['MFAEnabled'].sum()
    mfa_percentage = (mfa_enabled / total_users) * 100 if total_users > 0 else 0
    
    # Summary metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Users", total_users)
    with col2:
        st.metric("MFA Enabled", mfa_enabled)
    with col3:
        st.metric("MFA Coverage", f"{mfa_percentage:.1f}%")
    
    # MFA Status Chart
    fig = px.pie(
        names=['MFA Enabled', 'MFA Disabled'],
        values=[mfa_enabled, total_users - mfa_enabled],
        title="MFA Status Distribution"
    )
    st.plotly_chart(fig)
    
    # User table
    st.subheader("User Details")
    st.dataframe(df)

def main():
    """Main application"""
    if not check_auth():
        render_login()
    else:
        df = load_mfa_data()
        if df is not None:
            render_dashboard(df)

if __name__ == "__main__":
    main()