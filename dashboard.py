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
        # Set the headers for the request
        headers = {
            'Authorization': f'Bearer {token}',
            'ConsistencyLevel': 'eventual'
        }
        
        # Make the request to the Microsoft Graph API
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=30
        )
        
        # If the request is successful, return the response as a JSON object
        if response.status_code == 200:
            return response.json()
            
        # If the request is not successful, get the error data and message
        error_data = response.json() if response.text else {}
        error_message = error_data.get('error', {}).get('message', '')
        
        # If the error is due to access denied, show an error message and clear the token
        if response.status_code in [401, 403]:
            st.error("🔑 Access Denied - Please check permissions and try again")
            st.session_state.token = None
            return None
        else:
            # Otherwise, show the error message
            st.error(f"API Error ({response.status_code}): {error_message}")
            
        return None
        
    except Exception as e:
        # If there is an exception, show the error message
        st.error(f"Error: {str(e)}")
        return None

def check_auth() -> bool:
    """Check if user is authenticated"""
    return 'token' in st.session_state and st.session_state.token is not None

def logout():
    """Clear the session state"""
    st.session_state.clear()
    st.success("👋 Logged out successfully!")

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

def get_device_code():
    """Get device code for authentication"""
    try:
        payload = {
            'client_id': 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',
            'scope': 'https://graph.microsoft.com/User.Read.All https://graph.microsoft.com/UserAuthenticationMethod.Read.All'
        }
        
        # Print request details for debugging
        st.write("Sending request with payload:", payload)
        
        response = requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            data=payload
        )
        
        # Print response details for debugging
        st.write("Response status code:", response.status_code)
        st.write("Response content:", response.text)
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API Error: Status Code {response.status_code}")
            st.error(f"Error Response: {response.text}")
        return None
            
    except requests.exceptions.RequestException as e:
        st.error(f"Network Error: {str(e)}")
        return None
    except ValueError as e:
        st.error(f"JSON Parsing Error: {str(e)}")
        return None
    except Exception as e:
        st.error(f"Unexpected Error: {str(e)}")
        return None



def poll_for_token(device_code):
    """Poll for token using device code"""
    payload = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id': 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',
        'device_code': device_code
    }
    
    response = requests.post(
        'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        data=payload
    )
    
    if response.status_code == 200:
        return response.json()
    return None

def render_login():
    st.title("🔐 Device Login Helper")

    if st.button("Get Authentication Code", type="primary"):
        with st.spinner("Getting authentication code..."):
            device_code_response = get_device_code()
            
            if device_code_response:
                st.session_state.user_code = device_code_response['user_code']
                st.session_state.device_code = device_code_response['device_code']
                
                st.markdown("""
                ### Steps to Sign In:
                
                1. Click this button to open Microsoft login:
                """)
                
                st.link_button("🌐 Open Microsoft Login Page", "https://microsoft.com/devicelogin", type="primary")
                
                st.markdown("""
                2. Copy this authentication code:
                """)
                
                # Display the generated code prominently
                st.code(st.session_state.user_code, language=None)
                
                st.markdown("""
                3. Paste the code on the Microsoft login page and complete your sign in
                """)


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
    render_login()