# dashboard.py

import streamlit as st
from streamlit.runtime.caching import cache_data, cache_resource
import requests
import time
from datetime import datetime, timezone, timedelta
import pandas as pd
import plotly.express as px
from collections import Counter


# Configure Streamlit
st.set_page_config(
    page_title="Microsoft Graph User Report",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Adjust cache duration to 6 hours
@st.cache_resource(ttl=21600)  # 6 hours in seconds
def init_session():
    if not hasattr(st.session_state, 'initialized'):
        st.session_state.initialized = True
        st.session_state.token = None
        st.session_state.data = []
        st.session_state.processing = False
        st.session_state.processed_count = 0

# Configure server settings
if not st.session_state.get('server_config'):
    st.session_state.server_config = True
    st.cache_data.clear()
    st.cache_resource.clear()
# Dashboard Functions
# Configuration
TENANT_ID = "0c354a30-f421-4d42-bd98-0d86e396d207"  
CLIENT_ID = "1b730954-1685-4b74-9bfd-dac224a7b894"
CHUNK_SIZE = 100
DISPLAY_UPDATE_FREQUENCY = 500
TOTAL_USERS_ESTIMATE = 13500
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

# Add this function to save partial results
def save_partial_results(df, filename_prefix):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.xlsx"
    df.to_excel(filename, index=False)
    return filename

# Modify the display_results function to include partial saves
def display_results(df):
    if df is not None and not df.empty:
        st.write(f"Total users processed: {len(df)}")
        st.dataframe(df)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("Export to Excel"):
                filename = save_partial_results(df, "user_report")
                st.success(f"Exported to {filename}!")
        with col2:
            if st.button("Export to CSV"):
                df.to_csv("user_report.csv", index=False)
                st.success("Exported to CSV!")
        with col3:
            if st.button("Save Partial Results"):
                filename = save_partial_results(df, "partial_results")
                st.success(f"Partial results saved to {filename}!")

@st.cache_data(ttl=21600, max_entries=100)  # Limit cache entries@st.cache_data(ttl=21600)  # Cache data for 6 hours
def process_users_chunk(users_chunk, token, headers):
    chunk_data = []
    for user in users_chunk:
        # Try both MFA status endpoints
        mfa_status = 'Disabled'  # Default status
        
        # Try first endpoint
        mfa_response = requests.get(
            f'https://graph.microsoft.com/beta/users/{user["id"]}/authentication/strongAuthenticationRequirements',
            headers=headers
        )
        
        if mfa_response.status_code == 200:
            mfa_data = mfa_response.json()
            if "value" in mfa_data and len(mfa_data["value"]) > 0:
                mfa_status = mfa_data["value"][0]["perUserMfaState"]
        
        # If still Disabled, try second endpoint
        if mfa_status == 'Disabled':
            mfa_response2 = requests.get(
                f'https://graph.microsoft.com/beta/users/{user["id"]}/authentication/requirements',
                headers=headers
            )
            
            if mfa_response2.status_code == 200:
                mfa_data2 = mfa_response2.json()
                if "perUserMfaState" in mfa_data2:
                    mfa_status = mfa_data2["perUserMfaState"]
        
        # Debug: Print MFA status for first user
        if len(chunk_data) == 0:
            st.write("Debug - User:", user.get('userPrincipalName'))
            st.write("Debug - Final MFA Status:", mfa_status)
        
        # Get license details
        license_response = requests.get(
            f'https://graph.microsoft.com/v1.0/users/{user["id"]}/licenseDetails',
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
        
        chunk_data.append({
            'Name': user.get('displayName', ''),
            'UserPrincipalName': user.get('userPrincipalName', ''),
            'Mail': user.get('mail', ''),
            'Account Status': 'Active' if user.get('accountEnabled', False) else 'Disabled',
            'MFA Status': mfa_status,
            'Assigned Licenses': ', '.join(licenses) if licenses else 'No License',
            'Last Interactive SignIn': user.get('signInActivity', {}).get('lastSignInDateTime', 'Never'),
            'Creation Date': user.get('createdDateTime', '')
        })
    
    return chunk_data

def get_all_user_data(token):
    # 设置请求头
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    users_data = []
    # 创建进度条和表格占位符
    progress_placeholder = st.empty()
    table_placeholder = st.empty()
    
    try:
        # Process users in chunks of 100
        CHUNK_SIZE = 100
        next_link = 'https://graph.microsoft.com/beta/users?$select=id,displayName,userPrincipalName,mail,createdDateTime,signInActivity,accountEnabled&$top=999'
        total_processed = 0
        
        while next_link:
            response = requests.get(next_link, headers=headers)
            if response.status_code != 200:
                st.error("Failed to fetch users")
                return None

            current_users = response.json().get('value', [])
            
            # Process users in chunks
            for i in range(0, len(current_users), CHUNK_SIZE):
                chunk = current_users[i:i + CHUNK_SIZE]
                chunk_data = process_users_chunk(chunk, token, headers)
                users_data.extend(chunk_data)
                
                total_processed += len(chunk)
                progress_placeholder.progress(min(total_processed / 13500, 1.0))  # Assuming 13500 total users
                progress_placeholder.write(f"Processed {total_processed} users...")
                
                # Update display every 500 users
                if total_processed % 500 == 0:
                    temp_df = pd.DataFrame(users_data)
                    table_placeholder.dataframe(temp_df)
            
            next_link = response.json().get('@odata.nextLink')
        
        progress_placeholder.empty()
        
        if not users_data:
            st.warning("No users found")
            return None
        
        df = pd.DataFrame(users_data)
        df['Creation Date'] = pd.to_datetime(df['Creation Date']).dt.strftime('%Y-%m-%d %H:%M:%S')
        df['Last Interactive SignIn'] = pd.to_datetime(df['Last Interactive SignIn']).dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Cache the final dataframe
        st.session_state.data = df
        return df
        
    except Exception as e:
        st.error(f"Error fetching data: {str(e)}")
        return None

# Add this function for getting detailed user information
# Add this function for getting detailed user information
def get_user_details(email, token):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    try:
        # Get user basic info
        user_response = requests.get(
            f'https://graph.microsoft.com/beta/users/{email}',
            headers=headers
        )
        
        if user_response.status_code != 200:
            st.error(f"User not found: {email}")
            return None
            
        user_data = user_response.json()
        
        # Get MFA status
        mfa_response = requests.get(
            f'https://graph.microsoft.com/beta/users/{user_data["id"]}/authentication/strongAuthenticationRequirements',
            headers=headers
        )
        
        mfa_status = 'Disabled'
        if mfa_response.status_code == 200:
            mfa_data = mfa_response.json()
            if "value" in mfa_data and len(mfa_data["value"]) > 0:
                mfa_status = mfa_data["value"][0]["perUserMfaState"]
        
        # Get license details
        license_response = requests.get(
            f'https://graph.microsoft.com/v1.0/users/{user_data["id"]}/licenseDetails',
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
        
        # Compile detailed user info
        user_details = {
            'Display Name': user_data.get('displayName', ''),
            'Email': user_data.get('userPrincipalName', ''),
            'Mail': user_data.get('mail', ''),
            'Job Title': user_data.get('jobTitle', ''),
            'Department': user_data.get('department', ''),
            'Office Location': user_data.get('officeLocation', ''),
            'Business Phone': user_data.get('businessPhones', [''])[0] if user_data.get('businessPhones') else '',
            'Mobile Phone': user_data.get('mobilePhone', ''),
            'Account Status': 'Active' if user_data.get('accountEnabled', False) else 'Disabled',
            'MFA Status': mfa_status,
            'Assigned Licenses': ', '.join(licenses) if licenses else 'No License',
            'Last Sign In': user_data.get('signInActivity', {}).get('lastSignInDateTime', 'Never'),
            'Created Date': user_data.get('createdDateTime', ''),
            'Account Type': 'Cloud' if user_data.get('onPremisesSyncEnabled') is None else 'Synced from On-Premises'
        }
        
        return user_details
        
    except Exception as e:
        st.error(f"Error fetching user details: {str(e)}")
        return None

# In your main app section, replace the else block after checking token with:
    else:
    # Add a container for the top right search
        with st.container():
            col1, col2, col3 = st.columns([6, 2, 2])
            with col1:
                st.write("Currently logged in")
            with col2:
                search_email = st.text_input("Search by Email", key="search_email")
            with col3:
                if st.button("Search User"):
                    if search_email:
                        with st.spinner("Fetching user details..."):
                            user_details = get_user_details(search_email, st.session_state.token)
                            if user_details:
                                # Create a popup dialog with user details
                                with st.expander("User Details", expanded=True):
                                    st.write("### User Information")
                                    for key, value in user_details.items():
                                        col1, col2 = st.columns([1, 3])
                                        with col1:
                                            st.write(f"**{key}:**")
                                        with col2:
                                            st.write(value)
    
    # Your existing code for Get All Users and Logout buttons
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
            
def cleanup_cache():
    """Clean up cache when session ends"""
    st.cache_data.clear()
    st.cache_resource.clear()

# Add this to the logout function
def logout():
    """Clear the session state and cache"""
    cleanup_cache()
    st.session_state.clear()
    st.success("👋 Logged out successfully!")            
