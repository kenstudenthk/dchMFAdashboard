# auth.py
import streamlit as st
import requests
import time
from datetime import datetime, timedelta
import json

def get_device_code():
    """Get device code for authentication"""
    try:
        payload = {
            'client_id': 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',  # Microsoft Graph Explorer client ID
            'scope': 'https://graph.microsoft.com/User.Read.All https://graph.microsoft.com/UserAuthenticationMethod.Read.All'
        }
        
        # Show request details for debugging
        st.write("Requesting device code with payload:", payload)
        
        response = requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            data=payload,
            timeout=30
        )
        
        # Show response details
        st.write("Response status code:", response.status_code)
        st.write("Response headers:", dict(response.headers))
        
        try:
            response_json = response.json()
            st.write("Response JSON:", response_json)
        except json.JSONDecodeError:
            st.write("Raw response text:", response.text)
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Error getting device code: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        st.error(f"Network error: {str(e)}")
        return None
    except Exception as e:
        st.error(f"Unexpected error: {str(e)}")
        return None

def poll_for_token(device_code):
    """Poll for token using device code"""
    payload = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id': 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',
        'device_code': device_code
    }
    
    max_attempts = 60  # 5 minutes maximum
    for attempt in range(max_attempts):
        try:
            response = requests.post(
                'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                data=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 400:
                # Parse error
                error_data = response.json()
                error_code = error_data.get('error', '')
                
                # If still pending, continue polling
                if error_code == 'authorization_pending':
                    time.sleep(5)
                    continue
                    
                # If expired or denied, stop polling
                if error_code in ['expired_token', 'authorization_declined']:
                    st.error("Authentication was declined or expired. Please try again.")
                    return None
                    
            else:
                st.error(f"Unexpected response: {response.text}")
                return None
                
        except Exception as e:
            st.error(f"Error polling for token: {str(e)}")
            return None
            
        # Update progress
        progress = (attempt + 1) / max_attempts
        st.progress(progress, text=f"Waiting for authentication... {attempt + 1}/{max_attempts}")
        
    st.error("Authentication timed out. Please try again.")
    return None

def render_login():
    """Render the device code login page"""
    st.title("🔐 MFA Status Report")
    
    # Add tenant selection
    tenant_options = {
        "common": "Any Microsoft Account",
        "organizations": "Work/School Accounts Only",
        "consumers": "Personal Accounts Only"
    }
    
    selected_tenant = st.selectbox(
        "Select Account Type",
        options=list(tenant_options.keys()),
        format_func=lambda x: tenant_options[x],
        help="Choose the type of Microsoft account you want to use"
    )
    
    if st.button("Sign In with Microsoft"):
        st.info("Starting authentication process...")
        
        # Get device code
        device_code_response = get_device_code()
        
        if device_code_response:
            # Show user code and instructions
            st.markdown(f"""
            ### Please follow these steps to sign in:

            1. Visit [microsoft.com/devicelogin](https://microsoft.com/devicelogin)
            2. Enter this code: `{device_code_response['user_code']}`
            3. Follow the instructions to sign in
            
            The code will expire in {device_code_response.get('expires_in', 900)} seconds.
            """)
            
            # Create container for polling status
            status_container = st.empty()
            
            # Poll for token
            token_response = poll_for_token(device_code_response['device_code'])
            
            if token_response and 'access_token' in token_response:
                # Store token and timestamp
                st.session_state.token = token_response['access_token']
                st.session_state.token_timestamp = datetime.now()
                if 'refresh_token' in token_response:
                    st.session_state.refresh_token = token_response['refresh_token']
                st.success("✅ Authentication successful!")
                st.rerun()
        else:
            st.error("""
            Authentication setup failed. Please try:
            1. Refreshing the page
            2. Using a different browser
            3. Checking your network connection
            """)

    # Add troubleshooting section
    with st.expander("🔍 Troubleshooting"):
        st.markdown("""
        If you're having trouble signing in:
        
        1. **Network Issues**
           - Check your internet connection
           - Try disabling VPN if you're using one
           - Ensure you can access Microsoft URLs
        
        2. **Browser Issues**
           - Try using a different browser
           - Clear browser cache and cookies
           - Enable third-party cookies
        
        3. **Account Issues**
           - Ensure you're using the correct account type
           - Check if your account has the necessary permissions
           - Contact your IT admin if needed
        
        4. **Common Error Messages**
           - "Invalid grant": Try signing in again
           - "Unauthorized client": Contact support
           - "Invalid scope": Contact support
        """)

    st.markdown("""
    ### About This Sign-In Method
    - Secure device code flow authentication
    - No need to copy/paste tokens
    - Works with:
        - Multi-factor authentication (MFA)
        - Conditional access policies
        - Single sign-on (SSO)
    
    ### Required Permissions
    This application needs:
    - User.Read.All
    - UserAuthenticationMethod.Read.All
    """)
