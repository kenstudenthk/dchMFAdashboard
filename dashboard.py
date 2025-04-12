# dashboard.py

import streamlit as st
import requests
import time
from datetime import datetime, timezone, timedelta
import pandas as pd
import plotly.express as px
from collections import Counter

# Configure Streamlit
st.set_page_config(
    page_title="Microsoft Graph User Report",
    layout="wide"
)

# Initialize all session state variables in one place
if not st.session_state.get('initialized', False):
    st.session_state.initialized = True
    st.session_state.token = None
    st.session_state.data = []
    st.session_state.processing = False
    st.session_state.processed_count = 0
    st.cache_data.clear()
    
# Disable automatic refresh
st.cache_resource(ttl=3600)  # Cache resources for 1 hour

# Dashboard Functions
TENANT_ID = "0c354a30-f421-4d42-bd98-0d86e396d207"  
CLIENT_ID = "1b730954-1685-4b74-9bfd-dac224a7b894"
BATCH_SIZE = 500
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
        return response.json() if response.status_code == 200 else None
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
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return None

def display_results(df):
    if df is not None and not df.empty:
        st.write(f"Total users found: {len(df)}")
        st.dataframe(df)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Export to Excel"):
                df.to_excel("user_report.xlsx", index=False)
                st.success("Exported to Excel!")
        with col2:
            if st.button("Export to CSV"):
                df.to_csv("user_report.csv", index=False)
                st.success("Exported to CSV!")

def get_all_user_data(token):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    users_data = []
    progress_placeholder = st.empty()
    table_placeholder = st.empty()
    
    try:
        # Test the token
        test_response = requests.get(
            'https://graph.microsoft.com/beta/users?$top=1',  # Note: using beta endpoint
            headers=headers
        )
        if test_response.status_code != 200:
            st.error(f"API test failed. Status code: {test_response.status_code}")
            return None

        # Get all users with pagination
        next_link = 'https://graph.microsoft.com/beta/users?$select=id,displayName,userPrincipalName,mail,createdDateTime,signInActivity,accountEnabled&$top=999'
        total_processed = 0
        
        while next_link:
            response = requests.get(next_link, headers=headers)
            if response.status_code != 200:
                st.error("Failed to fetch users")
                return None

            current_users = response.json().get('value', [])
            progress_placeholder.write(f"Processing batch of {len(current_users)} users...")
            
            for user in current_users:
                # Get MFA status using authentication/requirements endpoint
                mfa_response = requests.get(
                    f'https://graph.microsoft.com/beta/users/{user["id"]}/authentication/requirements',
                    headers=headers
                )
                
                # Initialize MFA status
                mfa_status = 'Unknown'  # Default status
                
                # Process MFA status
                if mfa_response.status_code == 200:
                    mfa_data = mfa_response.json()
                    
                    # Debug: Print MFA response for first user
                    if total_processed == 0:
                        st.write("First user MFA response:", mfa_data)
                    
                    # Get perUserMfaState
                    mfa_status = mfa_data.get('perUserMfaState', 'Unknown')
                
                # Get license details
                license_response = requests.get(
                    f'https://graph.microsoft.com/v1.0/users/{user["id"]}/licenseDetails',
                    headers=headers
                )
                
                # Process licenses
                licenses = []
                if license_response.status_code == 200:
                    for license in license_response.json().get('value', []):
                        sku = license.get('skuPartNumber', '')
                        if 'ENTERPRISEPACK' in sku:
                            licenses.append('Office365 E3')
                        elif 'STANDARDPACK' in sku:
                            licenses.append('Office365 E1')
                
                # Compile user data
                users_data.append({
                    'Name': user.get('displayName', ''),
                    'UserPrincipalName': user.get('userPrincipalName', ''),
                    'Mail': user.get('mail', ''),
                    'Account Status': 'Active' if user.get('accountEnabled', False) else 'Disabled',
                    'MFA Status': mfa_status,
                    'Assigned Licenses': ', '.join(licenses) if licenses else 'No License',
                    'Last Interactive SignIn': user.get('signInActivity', {}).get('lastSignInDateTime', 'Never'),
                    'Creation Date': user.get('createdDateTime', '')
                })
                
                total_processed += 1
                if total_processed % 50 == 0:
                    progress_placeholder.write(f"Processed {total_processed} users...")
                    if users_data:
                        df = pd.DataFrame(users_data)
                        table_placeholder.dataframe(df)
            
            next_link = response.json().get('@odata.nextLink')
        
        progress_placeholder.empty()
        
        if not users_data:
            st.warning("No users found")
            return None
        
        df = pd.DataFrame(users_data)
        # Convert datetime columns
        df['Creation Date'] = pd.to_datetime(df['Creation Date']).dt.strftime('%Y-%m-%d %H:%M:%S')
        df['Last Interactive SignIn'] = pd.to_datetime(df['Last Interactive SignIn']).dt.strftime('%Y-%m-%d %H:%M:%S')
        return df
        
    except Exception as e:
        st.error(f"Error fetching data: {str(e)}")
        return None
    
def filter_data(df):
    st.write("### Filter Users")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        account_status = st.multiselect(
            "Account Status",
            options=['Active', 'Disabled'],
            default=['Active', 'Disabled']
        )
    
    with col2:
        mfa_status = st.multiselect(
            "MFA Status",
            options=sorted(df['MFA Status'].unique()),  # Dynamic options based on actual data
            default=sorted(df['MFA Status'].unique())
        )
    
    with col3:
        license_filter = st.text_input(
            "License Contains (e.g., E3, E1)",
            ""
        )
    
    # Apply filters
    filtered_df = df[
        (df['Account Status'].isin(account_status)) &
        (df['MFA Status'].isin(mfa_status))
    ]
    
    if license_filter:
        filtered_df = filtered_df[filtered_df['Assigned Licenses'].str.contains(license_filter, case=False, na=False)]
    
    return filtered_df

# Main app
st.title("Microsoft Graph User Report")

if not st.session_state.token:
    if st.button("Login to Microsoft"):
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
else:
    st.write("Currently logged in")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Get All Users"):
            df = get_all_user_data(st.session_state.token)
            if df is not None:
                st.write("### All Users Report")
                st.write(f"Total Users: {len(df)}")
                st.dataframe(df)
                
                # Show filtered report
                st.write("### Filtered Report")
                filtered_df = filter_data(df)
                st.write(f"Filtered Users: {len(filtered_df)}")
                st.dataframe(filtered_df)
                
                # Export options
                st.write("### Export Options")
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    if st.button("Export All Users (Excel)"):
                        df.to_excel("all_users_report.xlsx", index=False)
                        st.success("Exported all users to Excel!")
                with col2:
                    if st.button("Export All Users (CSV)"):
                        df.to_csv("all_users_report.csv", index=False)
                        st.success("Exported all users to CSV!")
                with col3:
                    if st.button("Export Filtered Users (Excel)"):
                        filtered_df.to_excel("filtered_users_report.xlsx", index=False)
                        st.success("Exported filtered users to Excel!")
                with col4:
                    if st.button("Export Filtered Users (CSV)"):
                        filtered_df.to_csv("filtered_users_report.csv", index=False)
                        st.success("Exported filtered users to CSV!")
    
    with col2:
        if st.button("Logout"):
            st.session_state.token = None
            st.rerun()
