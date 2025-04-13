# dashboard.py

import streamlit as st
from streamlit.runtime.caching import cache_data, cache_resource
import requests
import time
from datetime import datetime, timezone, timedelta
import pandas as pd
import plotly.express as px
from collections import Counter
from io import BytesIO
import pandas as pd
import os
from pathlib import Path
import traceback


# Configure Streamlit
st.set_page_config(
    page_title="Microsoft Graph User Report",
    layout="wide",
    initial_sidebar_state="collapsed"
)

def get_default_save_path():
    """Get default save path based on operating system"""
    if os.name == 'nt':  # Windows
        # Try Desktop first, fallback to Documents
        desktop = os.path.join(os.path.expanduser('~'), 'Desktop', 'MFAReports')
        if os.access(os.path.dirname(desktop), os.W_OK):
            return desktop
        return os.path.join(os.path.expanduser('~'), 'Documents', 'MFAReports')
    else:  # Mac/Linux
        return os.path.join(os.path.expanduser('~'), 'Documents', 'MFAReports')

def init_session_state():
    defaults = {
        'token': None,
        'data': [],
        'processing': False,
        'processed_count': 0,
        'df': None,
        'show_report': False,
        'authentication_in_progress': False,
        'device_code_response': None,
        'save_path': get_default_save_path(),
        'show_path_input': False,
        'save_to_sharepoint': False,
        'sharepoint_site': '',
        'sharepoint_folder': '',
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
# Dashboard Functions
# Configuration
TENANT_ID = "0c354a30-f421-4d42-bd98-0d86e396d207"  
CLIENT_ID = "1b730954-1685-4b74-9bfd-dac224a7b894"
CHUNK_SIZE = 100
DISPLAY_UPDATE_FREQUENCY = 500
TOTAL_USERS_ESTIMATE = 13500       
        
# Call the initialization function at the start
init_session_state()        
# Adjust cache duration to 6 hours
@st.cache_resource(ttl=21600)  # 6 hours in seconds

def select_save_path():
    """Let user select where to save files"""
    st.sidebar.markdown("### Save Location Settings")
    
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        # Simple text showing current path
        st.write("Current save path:")
    with col2:
        # Button to change path
        if st.button("Change Path"):
            st.session_state.show_path_input = True
    
    if 'show_path_input' not in st.session_state:
        st.session_state.show_path_input = False
        
    if st.session_state.show_path_input:
        new_path = st.sidebar.text_input(
            "Enter save path:",
            value=st.session_state.save_path,
            help="Enter the full path where you want to save files"
        )
        
        col1, col2 = st.sidebar.columns(2)
        with col1:
            if st.button("Save"):
                if os.path.exists(new_path):
                    st.session_state.save_path = new_path
                    st.session_state.show_path_input = False
                    st.sidebar.success("✅ Path updated!")
                else:
                    try:
                        os.makedirs(new_path, exist_ok=True)
                        st.session_state.save_path = new_path
                        st.session_state.show_path_input = False
                        st.sidebar.success("✅ Created new directory!")
                    except Exception as e:
                        st.sidebar.error(f"❌ Could not create directory: {str(e)}")
        with col2:
            if st.button("Cancel"):
                st.session_state.show_path_input = False
    
    # Always show current path
    st.sidebar.info(f"Files will be saved to:\n{st.session_state.save_path}")
    
    return st.session_state.save_path
def get_desktop_path():

    return str(Path.home() / "Desktop")

# Add this function to handle path management
def handle_save_path():
    st.sidebar.markdown("### Save Location Settings")
    
    # Create default directory if it doesn't exist
    try:
        os.makedirs(st.session_state.save_path, exist_ok=True)
    except Exception as e:
        st.sidebar.error(f"❌ Cannot create default directory: {str(e)}")
    
    # Show current path
    st.sidebar.info(f"Current save path:\n{st.session_state.save_path}")
    
    # Button to change path
    if st.sidebar.button("Change Save Location"):
        st.session_state.show_path_input = True
        
    # Show path input if requested
    if st.session_state.get('show_path_input', False):
        # Show different help text based on OS
        if os.name == 'nt':
            help_text = "Example: C:\\Users\\YourName\\Documents\\MFAReports"
        else:
            help_text = "Example: ~/Documents/MFAReports"
            
        new_path = st.sidebar.text_input(
            "Enter new save path:",
            value=st.session_state.save_path,
            help=help_text
        )
        
        # Expand user directory if ~ is used (works on both Windows and Mac)
        new_path = os.path.expanduser(new_path)
        
        col1, col2 = st.sidebar.columns(2)
        with col1:
            if st.button("Confirm"):
                try:
                    os.makedirs(new_path, exist_ok=True)
                    # Test write permissions
                    test_file = os.path.join(new_path, 'test.txt')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    
                    st.session_state.save_path = new_path
                    st.session_state.show_path_input = False
                    st.sidebar.success("✅ Path updated!")
                except PermissionError:
                    st.sidebar.error("❌ No permission to write to this location. Please choose another folder.")
                except Exception as e:
                    st.sidebar.error(f"❌ Error: {str(e)}")
        with col2:
            if st.button("Cancel"):
                st.session_state.show_path_input = False

def save_to_local(df_batch, filename):
    try:
        save_path = st.session_state.save_path
        
        # Ensure directory exists
        os.makedirs(save_path, exist_ok=True)
        
        full_path = os.path.join(save_path, filename)
        
        if os.path.exists(full_path):
            existing_df = pd.read_excel(full_path)
            combined_df = pd.concat([existing_df, df_batch], ignore_index=True)
            combined_df = combined_df.drop_duplicates(subset=['userPrincipalName'], keep='last')
            st.toast(f"Updated existing file. Total records: {len(combined_df)}", icon="📤")
        else:
            combined_df = df_batch
            st.toast("Creating new file", icon="📝")
        
        combined_df.to_excel(full_path, index=False)
        st.toast(f"Successfully saved to: {filename}", icon="✅")
        
        # Show full path in sidebar
        st.sidebar.success(f"File saved to:\n{full_path}")
        
        return combined_df
    except PermissionError:
        st.error("❌ No permission to save file. Please choose another location.")
        return None
    except Exception as e:
        st.error(f"❌ Error saving file: {str(e)}")
        return None
# Update init_session_state
def init_session_state():
    defaults = {
        'token': None,
        'data': [],
        'processing': False,
        'processed_count': 0,
        'df': None,
        'show_report': False,
        'authentication_in_progress': False,
        'device_code_response': None,
        'save_path': str(Path.home() / "Desktop"),  # Default path
        'show_path_input': False  # For path selection UI
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

def get_last_processed_user(token):
    try:
        # Try to get from SharePoint first
        sharepoint_data = None
        local_data = None
        
        # Check SharePoint
        try:
            filename = "user_report.xlsx"
            url = f"https://graph.microsoft.com/v1.0/me/drive/root:/{filename}:/content"
            response = requests.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                stream=True
            )
            
            if response.status_code == 200:
                excel_buffer = BytesIO(response.content)
                sharepoint_data = pd.read_excel(excel_buffer)
        except Exception as e:
            print(f"Error reading SharePoint file: {e}")

        # Check local file
        try:
            desktop_path = get_desktop_path()
            local_file = os.path.join(desktop_path, "user_report.xlsx")
            if os.path.exists(local_file):
                local_data = pd.read_excel(local_file)
        except Exception as e:
            print(f"Error reading local file: {e}")

        # Compare and get the most recent data
        if sharepoint_data is not None and local_data is not None:
            # Use the file with more records
            if len(sharepoint_data) >= len(local_data):
                return sharepoint_data
            return local_data
        elif sharepoint_data is not None:
            return sharepoint_data
        elif local_data is not None:
            return local_data
            
        return None
    except Exception as e:
        st.error(f"Error getting last processed user: {e}")
        return None


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


def save_to_sharepoint(df_batch, site_name, folder_path, filename):
    """Save dataframe to SharePoint"""
    try:
        # Get SharePoint site
        site = get_sharepoint_site(site_name)
        if not site:
            st.error("❌ Could not connect to SharePoint site")
            return None

        # Get the folder
        folder = site.get_folder_by_server_relative_url(folder_path)
        
        # Create a temporary Excel file
        temp_file = "temp_upload.xlsx"
        df_batch.to_excel(temp_file, index=False)
        
        # Read the file content
        with open(temp_file, 'rb') as file_content:
            content = file_content.read()

        # Upload to SharePoint
        folder.upload_file(filename, content)
        
        # Clean up temp file
        os.remove(temp_file)
        
        st.success(f"✅ Successfully saved to SharePoint: {filename}")
        return True
        
    except Exception as e:
        st.error(f"❌ Error saving to SharePoint: {str(e)}")
        return None

def get_sharepoint_site(site_name):
    """Get SharePoint site using Graph API"""
    try:
        # Get access token from session state
        token = st.session_state.token
        
        if not token:
            st.error("❌ No access token available")
            return None
            
        # Set up headers for Graph API
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Get SharePoint site ID
        site_url = f"https://graph.microsoft.com/v1.0/sites/{site_name}"
        response = requests.get(site_url, headers=headers)
        
        if response.status_code != 200:
            st.error(f"❌ Failed to get SharePoint site: {response.text}")
            return None
            
        site_data = response.json()
        return site_data
        
    except Exception as e:
        st.error(f"❌ Error connecting to SharePoint: {str(e)}")
        return None

# Add this to your main processing function where you save the files
def save_files(df_batch):
    try:
        # Local save
        filename = f"MFA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        local_save = save_to_local(df_batch, filename)
        
        # SharePoint save (if configured)
        if st.session_state.get('save_to_sharepoint', False):
            sharepoint_site = st.session_state.get('sharepoint_site')
            sharepoint_folder = st.session_state.get('sharepoint_folder')
            
            if sharepoint_site and sharepoint_folder:
                sharepoint_save = save_to_sharepoint(
                    df_batch,
                    sharepoint_site,
                    sharepoint_folder,
                    filename
                )
                if sharepoint_save:
                    st.success("✅ Saved to both local and SharePoint")
                else:
                    st.warning("⚠️ Saved locally but SharePoint save failed")
            else:
                st.warning("⚠️ SharePoint settings not configured")
        
        return local_save
        
    except Exception as e:
        st.error(f"❌ Error saving files: {str(e)}")
        return None

# Add SharePoint settings to your sidebar
def show_sharepoint_settings():
    st.sidebar.markdown("### SharePoint Settings")
    
    # Toggle for SharePoint save
    enable_sharepoint = st.sidebar.checkbox(
        "Save to SharePoint",
        value=st.session_state.get('save_to_sharepoint', False),
        key='enable_sharepoint'
    )
    
    if enable_sharepoint:
        # SharePoint site input
        sharepoint_site = st.sidebar.text_input(
            "SharePoint Site",
            value=st.session_state.get('sharepoint_site', ''),
            help="Example: contoso.sharepoint.com:/sites/YourSiteName"
        )
        
        # SharePoint folder input
        sharepoint_folder = st.sidebar.text_input(
            "SharePoint Folder Path",
            value=st.session_state.get('sharepoint_folder', ''),
            help="Example: Shared Documents/MFA Reports"
        )
        
        # Save settings to session state
        st.session_state.save_to_sharepoint = True
        st.session_state.sharepoint_site = sharepoint_site
        st.session_state.sharepoint_folder = sharepoint_folder
    else:
        st.session_state.save_to_sharepoint = False

def refresh_token_with_device_code():
    """Get a new token using device code flow"""
    try:
        device_code_response = get_device_code()
        if device_code_response:
            st.warning("""Your session has expired. Please authenticate again.
            Visit: https://microsoft.com/devicelogin
            And enter the code shown below:""")
            st.code(device_code_response['user_code'])
            
            device_code = device_code_response['device_code']
            token_response = poll_for_token(device_code)
            
            if token_response and 'access_token' in token_response:
                st.session_state.token = token_response['access_token']
                st.success("Successfully refreshed authentication!")
                return True
    except Exception as e:
        st.error(f"Error refreshing token: {str(e)}")
    return False

def get_all_user_data(token, resume=False):
    try:
        # Check token validity before starting
        if not check_token_validity(token):
            st.warning("Authentication expired. Refreshing token...")
            if not refresh_token_with_device_code():
                st.error("Failed to refresh authentication. Please try again.")
                return None
            # Get new token from session state
            token = st.session_state.token
            
        all_users = []
        batch_size = 100
        
        if resume:
            last_processed_df = get_last_processed_user(token)
            if last_processed_df is not None:
                all_users = last_processed_df.to_dict('records')
                st.toast(f"Found {len(all_users)} previously processed users", icon="📂")
        
        # Determine starting point
        if resume and last_processed_df is not None and not last_processed_df.empty:
            last_user = last_processed_df.iloc[-1]
            next_link = f"https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled&$filter=userPrincipalName gt '{last_user['userPrincipalName']}'"
            st.toast(f"Resuming from user: {last_user['userPrincipalName']}", icon="▶️")
        else:
            next_link = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled"
        
        progress_container = st.empty()
        data_container = st.empty()
        
        while next_link:
            response = requests.get(
                next_link,
                headers={"Authorization": f"Bearer {token}"}
            )
            
            if response.status_code == 200:
                data = response.json()
                batch_users = data.get('value', [])
                all_users.extend(batch_users)
                
                df_batch = pd.DataFrame(batch_users)
                
                if len(df_batch) > 0:
                    filename = "user_report.xlsx"
                    
                    # Save to SharePoint
                    sharepoint_df = save_to_sharepoint(df_batch, filename, token)
                    
                    # Save to local
                    local_df = save_to_local(df_batch, filename)
                    
                    # Use SharePoint data for display (or local if SharePoint fails)
                    display_df = sharepoint_df if sharepoint_df is not None else local_df
                    
                    if display_df is not None:
                        progress_container.write(f"""
                        ### Progress Update
                        - Total users processed: {len(all_users)}
                        - Current batch size: {len(df_batch)}
                        - Latest save timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                        """)
                        data_container.dataframe(display_df)
                
                next_link = data.get('@odata.nextLink', None)
                
                if not next_link:
                    st.toast("Data collection completed! 🎉", icon="🏁")
            else:
                st.toast("Failed to fetch users!", icon="❌")
                break
                
        df = pd.DataFrame(all_users)
        return df
        
    except Exception as e:
        st.toast(f"Error in data processing: {str(e)}", icon="❌")
        return None

def handle_token_validation():
    if not st.session_state.token:
        return False
    
    if not check_token_validity(st.session_state.token):
        st.warning("Authentication expired. Refreshing token...")
        if not refresh_token_with_device_code():
            st.error("Failed to refresh authentication. Please try again.")
            return False
    return True

def main():
    st.title("Microsoft Graph User Report")

    # Add save location settings to sidebar
    if st.session_state.token:  # Only show when logged in
        handle_save_path() # This will update st.session_state.save_path
        show_sharepoint_settings()  # SharePoint settings
        # Show current save location
        st.sidebar.info(f"""
        Current save location:
        {st.session_state.save_path}
        """)
    # Authentication Flow
    if not st.session_state.token:
        # Show login button if not in authentication process
        if not st.session_state.authentication_in_progress:
            if st.button("Login to Microsoft", key="login_button"):
                st.session_state.device_code_response = get_device_code()
                if st.session_state.device_code_response:
                    st.session_state.authentication_in_progress = True
                    st.rerun()
        
        # Show device code flow if in authentication process
        if st.session_state.authentication_in_progress:
            st.markdown("""
            ### Please follow these steps:
            1. Go to: https://microsoft.com/devicelogin
            2. Enter this code:
            """)
            st.code(st.session_state.device_code_response['user_code'])
            
            with st.spinner("Waiting for authentication..."):
                interval = int(st.session_state.device_code_response.get('interval', 5))
                expires_in = int(st.session_state.device_code_response.get('expires_in', 900))
                start_time = time.time()
                
                while time.time() - start_time < expires_in:
                    token_response = poll_for_token(st.session_state.device_code_response['device_code'])
                    if token_response:
                        st.session_state.token = token_response['access_token']
                        st.session_state.authentication_in_progress = False
                        st.session_state.device_code_response = None
                        st.success("Successfully logged in!")
                        st.rerun()
                        break
                    time.sleep(interval)
                
                # Handle timeout
                st.error("Authentication timed out. Please try again.")
                st.session_state.authentication_in_progress = False
                st.session_state.device_code_response = None
                st.rerun()

    else:
        # Validate existing token
        if not handle_token_validation():
            st.session_state.token = None
            st.rerun()
            return

        # Show sidebar info if report exists
        if st.session_state.show_report:
            st.sidebar.markdown("""
            ### File Locations
            - SharePoint/OneDrive: root folder
            - Local: Desktop folder
            """)

        # Search Container
        with st.container():
            st.write("---")
            search_col1, search_col2, search_col3 = st.columns([2, 2, 1])
            with search_col2:
                search_email = st.text_input(
                    "Search User by Email", 
                    key="search_email", 
                    placeholder="Enter email address"
                )
            with search_col3:
                if st.button("Search", key="search_button"):
                    if search_email:
                        with st.spinner("Fetching user details..."):
                            user_details = get_user_details(search_email, st.session_state.token)
                            if user_details:
                                with st.expander("User Details", expanded=True):
                                    st.write("### User Information")
                                    for key, value in user_details.items():
                                        col1, col2 = st.columns([1, 3])
                                        with col1:
                                            st.write(f"**{key}:**")
                                        with col2:
                                            st.write(value)

        # Main Actions
        with st.container():
            st.write("---")
            action_col1, action_col2, action_col3 = st.columns(3)
            
            with action_col1:
                if st.button("Get All Users", key="get_users_button"):
                     st.write("Button clicked - starting process...")  # Debug message
                     df = get_all_user_data(st.session_state.token, resume=False)
                     st.write("Got response from get_all_user_data")  # Debug message
                     if df is not None:
                            st.session_state.df = df
                            st.session_state.show_report = True
                            st.success("Data collection complete!")
                     else:
                            st.error("Failed to collect data")

            with action_col2:
                if st.button("Resume Processing", key="resume_button"):
                    st.session_state.df = get_all_user_data(st.session_state.token, resume=True)
                    if st.session_state.df is not None:
                        st.session_state.show_report = True
                        st.success("Resume processing complete!")

            with action_col3:
                if st.button("Logout", key="logout_button"):
                    logout()
                    st.rerun()

        # Display Report
        if st.session_state.show_report and st.session_state.df is not None:
            st.write("### All Users Report")
            st.write(f"Total Users: {len(st.session_state.df)}")
            st.dataframe(st.session_state.df)
            
            st.write("### Filtered Report")
            filtered_df = filter_data(st.session_state.df)
            st.write(f"Filtered Users: {len(filtered_df)}")
            st.dataframe(filtered_df)
            
            # Export Options
            st.write("### Export Options")
            export_col1, export_col2, export_col3, export_col4 = st.columns(4)
            with export_col1:
                if st.button("Export All (Excel)", key="export_all_excel"):
                    st.session_state.df.to_excel("all_users_report.xlsx", index=False)
                    st.success("Exported all users to Excel!")
            with export_col2:
                if st.button("Export All (CSV)", key="export_all_csv"):
                    st.session_state.df.to_csv("all_users_report.csv", index=False)
                    st.success("Exported all users to CSV!")
            with export_col3:
                if st.button("Export Filtered (Excel)", key="export_filtered_excel"):
                    filtered_df.to_excel("filtered_users_report.xlsx", index=False)
                    st.success("Exported filtered users to Excel!")
            with export_col4:
                if st.button("Export Filtered (CSV)", key="export_filtered_csv"):
                    filtered_df.to_csv("filtered_users_report.csv", index=False)
                    st.success("Exported filtered users to CSV!")
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


# Add this function for getting detailed user informatio
def get_user_details(email, token, user_id=None):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    try:
        print(f"Getting details for user: {email}")  # Debug with print instead of st.write
        
        # Get user basic info
        user_response = requests.get(
            f'https://graph.microsoft.com/beta/users/{user_id}',
            headers=headers
        )
        
        if user_response.status_code != 200:
            print(f"Error getting user {email}: Status {user_response.status_code}")  # Debug with print
            return None
            
        user_data = user_response.json()
        print(f"Got basic info for: {email}")  # Debug with print
        
        # Get MFA status using authentication/requirements
        mfa_response = requests.get(
            f'https://graph.microsoft.com/beta/users/{user_data["id"]}/authentication/requirements',
            headers=headers
        )
        
        mfa_status = 'Disabled'
        if mfa_response.status_code == 200:
            mfa_data = mfa_response.json()
            mfa_status = 'Enabled' if mfa_data.get('state') == 'enabled' else 'Disabled'

        # Get license details
        license_response = requests.get(
            f'https://graph.microsoft.com/v1.0/users/{user_data["id"]}/licenseDetails',
            headers=headers
        )
        
        licenses = []
        has_required_license = False
        if license_response.status_code == 200:
            for license in license_response.json().get('value', []):
                sku = license.get('skuPartNumber', '')
                if sku == 'ENTERPRISEPACK':
                    licenses.append('Office365 E3')
                    has_required_license = True
                elif sku == 'STANDARDPACK':
                    licenses.append('Office365 E1')
                    has_required_license = True
                else:
                    licenses.append(sku)

        # Get sign-in activity and format dates
        signin_activity = user_data.get('signInActivity', {})
        last_signin = signin_activity.get('lastSignInDateTime', 'Never')
        if last_signin != 'Never':
            last_signin = datetime.strptime(last_signin, '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S')

        created_date = user_data.get('createdDateTime', '')
        if created_date:
            created_date = datetime.strptime(created_date, '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S')
        
        # Compile detailed user info
        user_details = {
            'Display Name': user_data.get('displayName', ''),
            'Mail': user_data.get('mail', ''),
            'UPN': user_data.get('userPrincipalName', ''),
            'Creation Date': created_date,
            'Last Interactive Sign In': last_signin,
            'Account Status': 'Active' if user_data.get('accountEnabled', False) else 'Disabled',
            'MFA Status': mfa_status,
            'Has E1/E3 License': 'Yes' if has_required_license else 'No',
            'Assigned Licenses': ', '.join(licenses) if licenses else 'No License'
        }
        
        return user_details
        
    except Exception as e:
        st.error(f"Error fetching user details: {str(e)}")
        return None

def get_all_user_data(token, resume=False):
    """Get all users with detailed information"""
    try:
        users = []
        next_link = 'https://graph.microsoft.com/beta/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,signInActivity'
        
                # Test API connection first
        test_response = requests.get(
            'https://graph.microsoft.com/v1.0/users?$top=1',
            headers={'Authorization': f'Bearer {token}'}
        )
        st.write(f"Test API call status: {test_response.status_code}")  # Debug message
        
        progress_bar = st.progress(0)
        st.write(f"Fetching batch of users from: {next_link}") 
        while next_link:
            response = requests.get(next_link, headers={'Authorization': f'Bearer {token}'})
            if response.status_code != 200:
                st.error("Failed to fetch users")
                st.write(f"Error response: {response.text}")  # Debug message
                return None
            
            data = response.json()
            batch = data.get('value', [])
            st.write(f"Retrieved {len(batch)} users in this batch")  # Debug message
            
            for user in batch:
                user_details = get_user_details(
                    email=user['userPrincipalName'],
                    token=token,
                    user_id=user['id']  # Pass the user ID from the batch
                )
                if user_details:
                    users.append(user_details)
            
            next_link = data.get('@odata.nextLink')
            progress = min(len(users) / 100, 1.0)
            progress_bar.progress(progress)
            
            st.write(f"Processed {len(users)} users so far")  # Debug message
            
        
        if users:
            df = pd.DataFrame(users)
            st.write(f"Created DataFrame with {len(df)} rows")  # Debug message
            return df
        else:
            st.warning("No users found")
            return None
    except Exception as e:
        st.error(f"Error fetching all users: {str(e)}")
        st.write(f"Full error: {traceback.format_exc()}")  # Debug message
        return None

# Then in your main app section:
if 'show_report' in st.session_state and st.session_state.show_report:
    st.write("### Report Summary")
    st.write(f"Total Users: {st.session_state.total_users}")
    st.write(f"Users meeting criteria: {st.session_state.filtered_users}")
    
    # Show filtered data
    st.write("### Filtered Results")
    st.dataframe(st.session_state.filtered_df)
    
    # Export options
    if len(st.session_state.filtered_df) > 0:
        col1, col2 = st.columns(2)
        with col1:
            # Excel export
            excel_buffer = io.BytesIO()
            st.session_state.filtered_df.to_excel(excel_buffer, index=False)
            excel_data = excel_buffer.getvalue()
            
            st.download_button(
                label="Download Report (Excel)",
                data=excel_data,
                file_name=f"MFA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
            
        with col2:
            # CSV export
            csv = st.session_state.filtered_df.to_csv(index=False)
            st.download_button(
                label="Download Report (CSV)",
                data=csv,
                file_name=f"MFA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

# Add a clear button if needed
    if st.button("Clear Report"):
        st.session_state.show_report = False
        if 'filtered_df' in st.session_state:
            del st.session_state.filtered_df
        if 'df' in st.session_state:
            del st.session_state.df
        st.rerun()
def filter_data(df):
    """Filter for active accounts with disabled MFA and E1/E3 license"""
    filtered_df = df[
        (df['Account Status'] == 'Active') & 
        (df['MFA Status'] == 'Disabled') &
        (df['Has E1/E3 License'] == 'Yes')
    ]
    
    # Keep only required columns in specified order
    columns = [
        'Display Name',
        'Mail',
        'UPN',
        'Creation Date',
        'Last Interactive Sign In'
    ]
    
    return filtered_df[columns]

# Add to your main processing section:
def process_and_export(df):
    if df is not None:
        filtered_df = filter_data(df)
        
        # Show summary
        st.write("### Summary")
        st.write(f"Total Users: {len(df)}")
        st.write(f"Users meeting criteria: {len(filtered_df)}")
        
        # Show filtered data
        st.write("### Filtered Results")
        st.dataframe(filtered_df)
        
        # Export options
        if len(filtered_df) > 0:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"MFA_Report_{timestamp}.csv"
            
            csv = filtered_df.to_csv(index=False)
            st.download_button(
                label="Download Report (CSV)",
                data=csv,
                file_name=filename,
                mime="text/csv"
            )

def check_token_validity(token):
    """Check if the token is valid by making a test request"""
    try:
        response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers={'Authorization': f'Bearer {token}'}
        )
        return response.status_code == 200
    except:
        return False



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
    
if __name__ == "__main__":
    main()