# dashboard.py

import streamlit as st
import requests
import time
from datetime import datetime, timezone, timedelta
import pandas as pd
import plotly.express as px
from collections import Counter

# Dashboard Functions
TENANT_ID = "0c354a30-f421-4d42-bd98-0d86e396d207"  
CLIENT_ID = "1b730954-1685-4b74-9bfd-dac224a7b894"
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



def get_device_code():
    """Get device code using tenant ID"""
    try:
        response = requests.post(
            f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/devicecode',
            data={
                'client_id': CLIENT_ID,  # Added this
                'resource': 'https://graph.microsoft.com'
            }
        )
        
        if response.status_code == 200:
            return response.json()
        st.error(f"Error response: {response.text}")
        return None
            
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

def poll_for_token(device_code):
    """Poll for token after user logs in"""
    try:
        response = requests.post(
            f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/token',
            data={
                'grant_type': 'device_code',
                'client_id': CLIENT_ID,
                'code': device_code,
                'resource': 'https://graph.microsoft.com'
            }
        )
        
        if response.status_code == 200:
            return response.json()
        
        # Don't show error for authorization_pending
        error_data = response.json()
        if error_data.get('error') != 'authorization_pending':
            st.error(f"Token error: {response.text}")
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
                
                st.link_button("🌐 Open Microsoft Device Login", "https://microsoft.com/devicelogin", type="primary")
                
                st.markdown("""
                2. Copy this authentication code:
                """)
                
                st.code(st.session_state.user_code, language=None)
                
                st.markdown("""
                3. Paste the code and sign in with your Microsoft account
                """)

                with st.spinner("Waiting for login completion..."):
                    interval = int(device_code_response.get('interval', 5))
                    expires_in = int(device_code_response.get('expires_in', 900))
                    start_time = time.time()
                    
                    while time.time() - start_time < expires_in:
                        token_response = poll_for_token(st.session_state.device_code)
                        if token_response:
                            st.session_state.token = token_response['access_token']
                            expires_in = int(token_response['expires_in'])
                            st.session_state.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
                            st.success("Successfully logged in!")
                            st.rerun()
                            break
                        time.sleep(interval)
            else:
                st.error("Failed to get authentication code. Please try again.")
                

        
def get_users_data(access_token):
    """Get users data with MFA and license information"""
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    users_data = []
    
    # Get all users
    response = requests.get(
        'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,createdDateTime,signInActivity',
        headers=headers
    )
    
    if response.status_code == 200:
        users = response.json().get('value', [])
        
        for user in users:
            user_id = user['id']
            
            # Get MFA status
            mfa_response = requests.get(
                f'https://graph.microsoft.com/beta/users/{user_id}/authentication/requirements',
                headers=headers
            )
            mfa_enabled = False if mfa_response.status_code == 200 else None
            
            # Get license details
            license_response = requests.get(
                f'https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails',
                headers=headers
            )
            
            licenses = []
            if license_response.status_code == 200:
                for license in license_response.json().get('value', []):
                    sku = license.get('skuPartNumber', '')
                    if 'ENTERPRISEPACK' in sku:
                        licenses.append('Office365 E3')
                    elif 'STANDARDPACK' in sku:
                        licenses.append('Office365 E1')
            
            # Only include users with E1 or E3 license and MFA disabled
            if licenses and not mfa_enabled:
                users_data.append({
                    'Name': user.get('displayName', ''),
                    'Mail': user.get('mail', ''),
                    'UPN': user.get('userPrincipalName', ''),
                    'Licenses': ', '.join(licenses),
                    'Creation Date': user.get('createdDateTime', ''),
                    'MFA Status': 'Disabled',
                    'Last Interactive SignIn': user.get('signInActivity', {}).get('lastSignInDateTime', '')
                })
    
    return pd.DataFrame(users_data)

def render_dashboard():
    st.title("📊 Microsoft Graph Dashboard")
    st.write("Welcome! You're successfully logged in.")
    
    if st.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

def main():
    if 'token' not in st.session_state:
        st.title("🔐 Microsoft Graph Authentication")
        
        if st.button("Login with Microsoft"):
            # Implement device code flow here
            # (Use the login code from previous response)
            pass
    else:
        # Get and display data
        df = get_users_data(st.session_state.token)
        render_dashboard(df)

if __name__ == "__main__":
    main()