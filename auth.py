# auth.py
import streamlit as st
import requests
from datetime import datetime, timedelta

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
            st.error(f"""🔑 Access Denied - Missing Required Permissions
            
Please ensure you have the following Microsoft Graph API permissions:
- User.Read.All
- UserAuthenticationMethod.Read.All

To add permissions:
1. Go to [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
2. Click on your profile icon → 'Modify Permissions'
3. Add the required permissions
4. Generate a new token and try again
            """)
            st.session_state.token = None
            return None
        elif response.status_code == 404:
            st.error(f"❌ Resource not found: {endpoint}")
        elif response.status_code == 429:
            st.warning("⚠️ Too many requests. Please wait a moment and try again.")
            retry_after = int(response.headers.get('Retry-After', 30))
            time.sleep(retry_after)
            return make_graph_request(endpoint, token)
        else:
            st.error(f"API Error ({response.status_code}): {error_message}")
            
        return None
        
    except requests.exceptions.Timeout:
        st.error("⚠️ Request timed out. Please try again.")
    except requests.exceptions.RequestException as e:
        st.error(f"Network error: {str(e)}")
    except Exception as e:
        st.error(f"Error: {str(e)}")
    
    return None

# auth.py
def verify_token(token: str) -> bool:
    """Verify if the token is valid and has required permissions"""
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'ConsistencyLevel': 'eventual'
        }
        
        # Decode and display token scopes
        import jwt
        token_parts = token.split('.')
        if len(token_parts) >= 2:
            # Decode middle part of token (payload)
            import base64
            payload = jwt.decode(token, options={"verify_signature": False})
            st.write("Token scopes:", payload.get('scp', 'No scopes found'))
            
        # Test permissions one by one
        st.write("Testing permissions:")
        
        # 1. Test basic access
        me_response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers=headers
        )
        st.write("✓ Basic access:", me_response.status_code == 200)
        
        # 2. Test User.Read.All
        users_response = requests.get(
            'https://graph.microsoft.com/v1.0/users?$select=id&$top=1',
            headers=headers
        )
        st.write("✓ User.Read.All:", users_response.status_code == 200)
        
        if users_response.status_code != 200:
            st.error("Cannot access user list. Error: " + str(users_response.json()))
            return False
            
        # 3. Test UserAuthenticationMethod.Read.All
        test_user_id = users_response.json()['value'][0]['id']
        auth_methods_response = requests.get(
            f'https://graph.microsoft.com/v1.0/users/{test_user_id}/authentication/methods',
            headers=headers
        )
        st.write("✓ UserAuthenticationMethod.Read.All:", auth_methods_response.status_code == 200)
        
        if auth_methods_response.status_code != 200:
            error_details = auth_methods_response.json()
            st.error(f"""
            Authentication Methods API Error:
            - Status Code: {auth_methods_response.status_code}
            - Error: {error_details.get('error', {}).get('code', 'Unknown')}
            - Message: {error_details.get('error', {}).get('message', 'No message')}
            
            To fix this:
            1. Go to Azure Portal: https://portal.azure.com
            2. Navigate to Azure Active Directory
            3. Enterprise Applications
            4. Search for "Microsoft Graph Explorer" or your custom app
            5. Select Permissions
            6. Click "Grant admin consent for [Your Organization]"
            7. Wait 5 minutes for permissions to propagate
            8. Get a new token from Graph Explorer
            """)
            return False
            
        return True
        
    except Exception as e:
        st.error(f"Error verifying permissions: {str(e)}")
        return False

# auth.py
import streamlit as st
import requests
import time
from datetime import datetime, timedelta

def get_device_code():
    """Get device code for authentication"""
    payload = {
        'client_id': 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',  # Microsoft Graph Explorer client ID
        'scope': 'User.Read.All UserAuthenticationMethod.Read.All'
    }
    
    response = requests.post(
        'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
        data=payload
    )
    
    if response.status_code == 200:
        return response.json()
    return None

def poll_for_token(device_code):
    """Poll for token using device code"""
    payload = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id': 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',
        'device_code': device_code
    }
    
    max_attempts = 60  # 5 minutes maximum
    for _ in range(max_attempts):
        response = requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            data=payload
        )
        
        if response.status_code == 200:
            return response.json()
        
        # Wait and try again
        time.sleep(5)
    
    return None

def render_login():
    """Render the device code login page"""
    st.title("🔐 MFA Status Report")
    
    if st.button("Sign In with Microsoft"):
        # Get device code
        device_code_response = get_device_code()
        if not device_code_response:
            st.error("Failed to start authentication process")
            return
            
        # Show user code and instructions
        st.markdown(f"""
        ### Please follow these steps to sign in:

        1. Go to: https://microsoft.com/devicelogin
        2. Enter code: `{device_code_response['user_code']}`
        3. Sign in with your Microsoft account
        4. Grant the requested permissions
        
        Waiting for you to complete the sign-in...
        """)
        
        # Create placeholder for progress
        progress_placeholder = st.empty()
        
        # Poll for token
        token_response = poll_for_token(device_code_response['device_code'])
        
        if token_response and 'access_token' in token_response:
            # Store token and timestamp
            st.session_state.token = token_response['access_token']
            st.session_state.token_timestamp = datetime.now()
            st.success("✅ Authentication successful!")
            st.rerun()
        else:
            st.error("Authentication failed or timed out. Please try again.")

    st.markdown("""
    ### About This Authentication Method
    - More secure than copying tokens
    - Handles permissions automatically
    - Works with MFA and conditional access
    - No need to copy/paste tokens
    
    ### Required Permissions
    This app needs these permissions:
    - User.Read.All
    - UserAuthenticationMethod.Read.All
    """)
def check_auth() -> bool:
    """Check if user is authenticated and token is not expired"""
    if 'token' not in st.session_state:
        return False
        
    if not st.session_state.token:
        return False
        
    if 'token_timestamp' in st.session_state:
        token_age = datetime.now() - st.session_state.token_timestamp
        if token_age > timedelta(hours=1):
            st.warning("🔄 Token has expired. Please login again.")
            logout(show_message=False)
            return False
            
    return True

def logout(show_message: bool = True):
    """Clear the session state to logout"""
    st.session_state.clear()
    if show_message:
        st.success("👋 Logged out successfully!")