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
    """Get device code for authentication"""
    try:
        response = requests.post(
            f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/devicecode',
            data={
                'client_id': CLIENT_ID,
                'scope': 'User.Read.All Group.ReadWrite.All UserAuthenticationMethod.ReadWrite.All AuditLog.Read.All'
            }
        )
        return response.json() if response.status_code == 200 else None
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
        return None
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

def get_user_data(token):
    """Get user data from Microsoft Graph"""
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    users_data = []
    
    try:
        # Get all users
        response = requests.get(
            'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,createdDateTime,signInActivity,accountEnabled',
            headers=headers
        )
        
        if response.status_code == 200:
            users = response.json().get('value', [])
            progress_bar = st.progress(0)
            
            for i, user in enumerate(users):
                if not user.get('accountEnabled', False):
                    continue
                
                user_id = user['id']
                
                # Get MFA status
                mfa_response = requests.get(
                    f'https://graph.microsoft.com/beta/users/{user_id}/authentication/requirements',
                    headers=headers
                )
                
                # Get license details
                license_response = requests.get(
                    f'https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails',
                    headers=headers
                )
                
                licenses = []
                has_target_license = False
                
                if license_response.status_code == 200:
                    for license in license_response.json().get('value', []):
                        sku = license.get('skuPartNumber', '')
                        if 'ENTERPRISEPACK' in sku:
                            licenses.append('Office365 E3')
                            has_target_license = True
                        elif 'STANDARDPACK' in sku:
                            licenses.append('Office365 E1')
                            has_target_license = True
                        elif 'EMS' in sku:
                            licenses.append('EMS E3')
                        elif 'EMSPREMIUM' in sku:
                            licenses.append('EMS E5')
                        elif 'Win10_VDA_E3' in sku:
                            licenses.append('Windows 10/11 Enterprise E3')
                
                # Only include users with E1/E3 license and MFA disabled
                if has_target_license and mfa_response.status_code == 200:
                    users_data.append({
                        'Name': user.get('displayName', ''),
                        'Mail': user.get('mail', ''),
                        'UPN': user.get('userPrincipalName', ''),
                        'Licenses': ', '.join(licenses),
                        'Creation Date': user.get('createdDateTime', ''),
                        'MFA Status': 'Disabled' if not mfa_response.json() else 'Enabled',
                        'Last Interactive SignIn': user.get('signInActivity', {}).get('lastSignInDateTime', 'Never')
                    })
                
                progress_bar.progress((i + 1) / len(users))
            
            progress_bar.empty()
            return pd.DataFrame(users_data)
    except Exception as e:
        st.error(f"Error fetching data: {str(e)}")
        return None

def main():
    st.title("Microsoft Graph User Report")
    
    # Initialize session state
    if 'token' not in st.session_state:
        st.session_state.token = None
    
    # Login section
    if not st.session_state.token:
        if st.button("Login to Microsoft", type="primary"):
            device_code_response = get_device_code()
            
            if device_code_response:
                st.markdown("""
                ### Please follow these steps:
                1. Go to: https://microsoft.com/devicelogin
                2. Enter this code:
                """)
                st.code(device_code_response['user_code'])
                
                with st.spinner("Waiting for authentication..."):
                    interval = int(device_code_response.get('interval', 5))
                    expires_in = int(device_code_response.get('expires_in', 900))
                    start_time = time.time()
                    
                    while time.time() - start_time < expires_in:
                        token_response = poll_for_token(device_code_response['device_code'])
                        if token_response:
                            st.session_state.token = token_response['access_token']
                            st.success("Successfully logged in!")
                            st.rerun()
                            break
                        time.sleep(interval)
    
    # Data retrieval section
    else:
        if st.button("Get User Report", type="primary"):
            with st.spinner("Fetching user data..."):
                df = get_user_data(st.session_state.token)
                
                if df is not None:
                    st.write(f"Found {len(df)} users with E1/E3 license and MFA disabled")
                    
                    # Filters
                    st.subheader("Filters")
                    col1, col2 = st.columns(2)
                    with col1:
                        license_filter = st.multiselect(
                            "License Type",
                            options=df['Licenses'].unique()
                        )
                    with col2:
                        mfa_filter = st.selectbox(
                            "MFA Status",
                            options=['All', 'Enabled', 'Disabled']
                        )
                    
                    # Apply filters
                    filtered_df = df.copy()
                    if license_filter:
                        filtered_df = filtered_df[filtered_df['Licenses'].isin(license_filter)]
                    if mfa_filter != 'All':
                        filtered_df = filtered_df[filtered_df['MFA Status'] == mfa_filter]
                    
                    # Display results
                    st.dataframe(filtered_df)
                    
                    # Export options
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Export to Excel"):
                            filtered_df.to_excel("user_report.xlsx", index=False)
                            st.success("Exported to Excel!")
                    with col2:
                        if st.button("Export to CSV"):
                            filtered_df.to_csv("user_report.csv", index=False)
                            st.success("Exported to CSV!")
        
        # Logout button
        if st.button("Logout"):
            st.session_state.token = None
            st.rerun()
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
                

def render_dashboard():
    st.title("📊 Microsoft Graph Dashboard")
    st.write("Welcome! You're successfully logged in.")
    
    if st.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

if __name__ == "__main__":
    main()