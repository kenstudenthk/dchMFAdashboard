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
            f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode',  # Updated to v2.0 endpoint
            data={
                'client_id': CLIENT_ID,
                'scope': 'https://graph.microsoft.com/.default'  # Updated scope
            }
        )
        if response.status_code == 200:
            return response.json()
        st.error(f"Failed to get device code: {response.text}")
        return None
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

def poll_for_token(device_code):
    """Poll for token after user logs in"""
    try:
        response = requests.post(
            f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token',  # Updated to v2.0 endpoint
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',  # Updated grant type
                'client_id': CLIENT_ID,
                'device_code': device_code,
                'scope': 'https://graph.microsoft.com/.default'  # Updated scope
            }
        )
        
        if response.status_code == 200:
            return response.json()
        
        error_data = response.json()
        if error_data.get('error') != 'authorization_pending':
            st.error(f"Token error: {response.text}")
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
        # Test the token first
        st.write("Testing API connection...")
        test_response = requests.get(
            'https://graph.microsoft.com/v1.0/users?$top=1',
            headers=headers
        )
        if test_response.status_code != 200:
            st.error(f"API test failed. Status code: {test_response.status_code}")
            st.error(f"Error message: {test_response.text}")
            return None

        # Get all users with pagination
        st.write("Fetching users...")
        next_link = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,createdDateTime,signInActivity,accountEnabled&$top=999'
        all_users = []
        
        while next_link:
            response = requests.get(next_link, headers=headers)
            
            if response.status_code != 200:
                st.error(f"Failed to fetch users. Status code: {response.status_code}")
                st.error(f"Error message: {response.text}")
                return None

            data = response.json()
            all_users.extend(data.get('value', []))
            next_link = data.get('@odata.nextLink')  # Get the next page link
            
            st.write(f"Fetched {len(all_users)} users so far...")

        st.write(f"Found {len(all_users)} total users")
        
        progress_bar = st.progress(0)
        progress_text = st.empty()
        
        # Process all users
        for i, user in enumerate(all_users):
            progress_text.write(f"Processing user {i+1} of {len(all_users)}: {user.get('displayName', 'Unknown')}")
            
            if not user.get('accountEnabled', False):
                continue
            
            user_id = user['id']
            
            # Get MFA status
            progress_text.write(f"Checking MFA status for {user.get('displayName', 'Unknown')}...")
            mfa_response = requests.get(
                f'https://graph.microsoft.com/beta/users/{user_id}/authentication/requirements',
                headers=headers
            )
            
            # Get license details
            progress_text.write(f"Checking license details for {user.get('displayName', 'Unknown')}...")
            license_response = requests.get(
                f'https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails',
                headers=headers
            )
            
            if license_response.status_code != 200:
                st.warning(f"Failed to get license details for {user.get('displayName', 'Unknown')}")
                continue
            
            licenses = []
            has_target_license = False
            
            for license in license_response.json().get('value', []):
                sku = license.get('skuPartNumber', '')
                if 'ENTERPRISEPACK' in sku:
                    licenses.append('Office365 E3')
                    has_target_license = True
                elif 'STANDARDPACK' in sku:
                    licenses.append('Office365 E1')
                    has_target_license = True
            
            # Check if MFA is required
            mfa_enabled = True  # Default to True
            if mfa_response.status_code == 200:
                mfa_data = mfa_response.json()
                mfa_enabled = bool(mfa_data)  # If requirements exist, MFA is enabled
            
            # Only include users with E1/E3 license and no MFA
            if has_target_license and not mfa_enabled:
                users_data.append({
                    'Name': user.get('displayName', ''),
                    'Mail': user.get('mail', ''),
                    'UPN': user.get('userPrincipalName', ''),
                    'Licenses': ', '.join(licenses),
                    'Creation Date': user.get('createdDateTime', ''),
                    'MFA Status': 'Disabled' if not mfa_enabled else 'Enabled',
                    'Last Interactive SignIn': user.get('signInActivity', {}).get('lastSignInDateTime', 'Never')
                })
            
            progress_bar.progress((i + 1) / len(all_users))
        
        progress_bar.empty()
        progress_text.empty()
        
        if not users_data:
            st.warning("No users found matching the criteria (E1/E3 license with MFA disabled)")
            return None
            
        df = pd.DataFrame(users_data)
        
        # Convert datetime strings to more readable format
        df['Creation Date'] = pd.to_datetime(df['Creation Date']).dt.strftime('%Y-%m-%d %H:%M:%S')
        df['Last Interactive SignIn'] = pd.to_datetime(df['Last Interactive SignIn']).dt.strftime('%Y-%m-%d %H:%M:%S')
        
        return df
        
    except Exception as e:
        st.error(f"Error fetching data: {str(e)}")
        return None

def main():
    st.title("Microsoft Graph User Report")
    
    if 'token' not in st.session_state:
        st.session_state.token = None
    
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
                st.write(device_code_response.get('message', ''))  # Show Microsoft's instructions
                
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
    else:
        st.write("Currently logged in")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Get User Report", type="primary"):
                with st.spinner("Fetching user data..."):
                    df = get_user_data(st.session_state.token)
                    
                    if df is not None and not df.empty:
                        st.write(f"Found {len(df)} users with E1/E3 license and MFA disabled")
                        
                        # Display results
                        st.dataframe(df)
                        
                        # Export options
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("Export to Excel"):
                                df.to_excel("user_report.xlsx", index=False)
                                st.success("Exported to Excel!")
                        with col2:
                            if st.button("Export to CSV"):
                                df.to_csv("user_report.csv", index=False)
                                st.success("Exported to CSV!")
        
        with col2:
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