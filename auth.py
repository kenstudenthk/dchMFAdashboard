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
        headers = {'Authorization': f'Bearer {token}'}
        
        # Check token info
        st.write("Checking token permissions...")
        
        # First test basic access
        me_response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers=headers
        )
        
        if me_response.status_code != 200:
            st.error("Basic access test failed. Please check if you're logged in correctly.")
            return False
            
        # Test User.Read.All permission
        users_response = requests.get(
            'https://graph.microsoft.com/v1.0/users?$select=id&$top=1',
            headers=headers
        )
        
        if users_response.status_code != 200:
            st.error("""
            Cannot access user list. 
            Please ensure User.Read.All permission has admin consent.
            Error details: {}
            """.format(users_response.json().get('error', {}).get('message', 'Unknown error')))
            return False
            
        # Test UserAuthenticationMethod.Read.All permission
        test_user_id = users_response.json()['value'][0]['id']
        auth_methods_response = requests.get(
            f'https://graph.microsoft.com/v1.0/users/{test_user_id}/authentication/methods',
            headers=headers
        )
        
        if auth_methods_response.status_code != 200:
            st.error("""
            Cannot access authentication methods. 
            Please ensure UserAuthenticationMethod.Read.All permission has admin consent.
            Error details: {}
            """.format(auth_methods_response.json().get('error', {}).get('message', 'Unknown error')))
            return False
            
        return True
        
    except Exception as e:
        st.error(f"Error verifying permissions: {str(e)}")
        return False

def render_login():
    """Render the login page"""
    st.title("🔐 MFA Status Report")
    
    st.markdown("""
    ### Required Permissions:
    This application requires the following Microsoft Graph permissions with **admin consent**:
    - User.Read.All
    - UserAuthenticationMethod.Read.All
    
    ### Get Your Access Token:
    1. Open [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
    2. Sign in with your admin account
    3. Click your profile icon → 'Modify Permissions'
    4. Add these permissions and ensure they show as "Consented":
        - User.Read.All
        - UserAuthenticationMethod.Read.All
    5. **Important**: If permissions show as "Not Consented":
        - You need admin rights to consent
        - Contact your Azure AD admin to grant consent
        - Or use Azure Portal to grant admin consent
    6. After permissions are consented, click profile icon → 'Access Token'
    7. Copy the token and paste below
    
    ### Alternative: Get Token via Azure Portal
    If Graph Explorer isn't working, try Azure Portal:
    1. Go to [Azure Portal](https://portal.azure.com)
    2. Navigate to Azure Active Directory
    3. App Registrations → New Registration
    4. Create a new app and note the Application ID
    5. API Permissions → Add Permission
    6. Add both required permissions
    7. Click 'Grant admin consent'
    8. Certificates & Secrets → New Client Secret
    9. Use these credentials to get a token via POST to:
       https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
    """)
    
    # Add expandable section for troubleshooting
    with st.expander("🔍 Troubleshooting Permission Issues"):
        st.markdown("""
        1. **Check Admin Rights**
           - You must be a Global Admin or Privileged Role Admin
           - Check your role in Azure AD Admin Portal
        
        2. **Verify Permission Status**
           - In Graph Explorer, permissions should show as "Consented"
           - Green checkmarks should appear next to permissions
        
        3. **Grant Admin Consent via Azure Portal**
           - Go to Azure Portal → Azure Active Directory
           - Enterprise Applications → Find your app
           - Permissions → Grant admin consent
        
        4. **Token Scope Issues**
           - Ensure token includes all required scopes
           - Try getting a new token after consent
           - Clear browser cache and cookies
        
        5. **Common Error Messages**
           - "Insufficient privileges": Need admin consent
           - "Invalid scope": Token missing permissions
           - "Access denied": Role or consent issues
        """)
    
    token = st.text_input("Access Token:", type="password")
    if st.button("Login"):
        if not token:
            st.error("⚠️ Please enter a token")
        elif verify_token(token):
            st.session_state.token = token
            st.session_state.token_timestamp = datetime.now()
            st.success("✅ Authentication successful!")
            st.rerun()
        else:
            st.error("❌ Please check the error messages above and try again.")

    st.markdown("""
    #### Token Tips:
    - Must be generated AFTER granting admin consent
    - Tokens expire after 1 hour
    - Clear browser cache if issues persist
    - Ensure you're using an admin account
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