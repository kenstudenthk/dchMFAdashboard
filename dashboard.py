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
def get_device_code_with_tenant():
    """Get device code using tenant ID"""
    try:
        tenant_id = "your_tenant_id"  # Replace with your tenant ID
        response = requests.post(
            f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode',
            data={
                'scope': 'https://graph.microsoft.com/User.Read.All https://graph.microsoft.com/UserAuthenticationMethod.Read.All'
            }
        )
        
        if response.status_code == 200:
            return response.json()
        return None
            
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

def get_device_code_with_client():
    """Get device code using client ID"""
    try:
        client_id = "your_client_id"  # Replace with your client ID
        response = requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            data={
                'client_id': client_id,
                'scope': 'https://graph.microsoft.com/User.Read.All https://graph.microsoft.com/UserAuthenticationMethod.Read.All'
            }
        )
        
        if response.status_code == 200:
            return response.json()
        return None
            
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

def poll_for_token(device_code, use_tenant=True):
    """Poll for token after user logs in"""
    try:
        tenant_id = "your_tenant_id"  # Replace with your tenant ID
        client_id = "your_client_id"  # Replace with your client ID
        
        # Choose URL based on whether using tenant or client ID
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token' if use_tenant else 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
        
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }
        
        # Add client_id if not using tenant
        if not use_tenant:
            data['client_id'] = client_id
            
        response = requests.post(token_url, data=data)
        
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

def check_token_valid():
    if 'token' not in st.session_state:
        return False
    if 'token_expiry' not in st.session_state:
        return False
    
    now = datetime.now(timezone.utc)
    if now >= st.session_state.token_expiry:
        return False
    
    return True

def render_login():
    st.title("🔐 Device Login")

    auth_type = st.radio(
        "Authentication Type",
        ["Tenant ID", "Client ID"],
        horizontal=True
    )

    if st.button("Get Authentication Code", type="primary"):
        with st.spinner("Getting authentication code..."):
            if auth_type == "Tenant ID":
                device_code_response = get_device_code_with_tenant()
            else:
                device_code_response = get_device_code_with_client()
            
            if device_code_response:
                st.session_state.user_code = device_code_response['user_code']
                st.session_state.device_code = device_code_response['device_code']
                
                st.markdown("""
                ### Steps to Sign In:
                
                1. Click this button to open Microsoft login:
                """)
                
                st.link_button("🌐 Open Microsoft Device Login", "https://microsoft.com/devicelogin", type="primary")
                
                st.markdown("""
                2. Copy this authentication code:
                """)
                
                st.code(st.session_state.user_code, language=None)
                
                st.markdown("""
                3. Paste the code and sign in with your Microsoft account
                """)

                with st.spinner("Waiting for login completion..."):
                    interval = device_code_response.get('interval', 5)
                    expires_in = device_code_response.get('expires_in', 900)
                    start_time = time.time()
                    
                    while time.time() - start_time < expires_in:
                        token_response = poll_for_token(
                            st.session_state.device_code, 
                            use_tenant=(auth_type == "Tenant ID")
                        )
                        if token_response:
                            st.session_state.token = token_response['access_token']
                            expires_in = token_response['expires_in']
                            st.session_state.token_expiry = datetime.now(timezone.utc).timestamp() + expires_in
                            st.success("Successfully logged in!")
                            st.rerun()
                            break
                        time.sleep(interval)
            else:
                st.error("Failed to get authentication code. Please try again.")

def render_dashboard():
    st.title("📊 Microsoft Graph Dashboard")
    st.write("Welcome! You're successfully logged in.")
    
    if st.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

def main():
    if 'token' not in st.session_state:
        st.session_state.token = None
    
    if not check_token_valid():
        render_login()
    else:
        render_dashboard()

if __name__ == "__main__":
    main()