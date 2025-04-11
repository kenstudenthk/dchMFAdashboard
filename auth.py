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

def render_login():
    """Render the login page"""
    st.title("🔐 MFA Status Report")
    
    # Add direct link to Azure AD admin consent
    tenant_id = st.text_input("Enter your Azure AD Tenant ID (optional):", 
                             help="Found in Azure Portal → Azure Active Directory → Overview")
    
    if tenant_id:
        admin_consent_url = f"https://login.microsoftonline.com/{tenant_id}/adminconsent?client_id=de8bc8b5-d9f9-48b1-a8ad-b748da725064"
        st.markdown(f"[Click here to grant admin consent directly]({admin_consent_url})")
    
    st.markdown("""
    ### Fix Permission Issues:
    
    1. **Method 1: Using Azure Portal**
       1. Go to [Azure Portal](https://portal.azure.com)
       2. Navigate to Azure Active Directory
       3. Click on Enterprise Applications
       4. Search for "Microsoft Graph Explorer"
       5. Click on Permissions
       6. Click "Grant admin consent for [Your Organization]"
       7. Wait 5 minutes
       8. Get new token from Graph Explorer
    
    2. **Method 2: Using Azure AD Admin Center**
       1. Go to [Azure AD Admin Center](https://aad.portal.azure.com)
       2. Enterprise Applications
       3. Microsoft Graph Explorer
       4. Permissions
       5. Grant admin consent
    
    3. **Method 3: Using PowerShell**
       ```powershell
       Connect-AzureAD
       $sp = Get-AzureADServicePrincipal -Filter "displayName eq 'Microsoft Graph Explorer'"
       $pending = Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $sp.ObjectId
       foreach($grant in $pending) {
           Set-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $grant.ObjectId -ConsentType "AllPrincipals"
       }
       ```
    
    ### Required Permissions:
    - User.Read.All
    - UserAuthenticationMethod.Read.All
    
    Both permissions must show as "Consented" in Graph Explorer.
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

    with st.expander("🔍 Still having issues?"):
        st.markdown("""
        1. **Clear Token Cache**
           - Clear browser cache
           - Sign out of Graph Explorer
           - Sign in again
           - Get new token
        
        2. **Verify Admin Role**
           ```
           1. Go to Azure Portal
           2. Azure Active Directory
           3. Users
           4. Find your account
           5. Assigned roles
           6. Verify you have Global Admin or Authentication Admin
           ```
        
        3. **Check App Registration**
           - Ensure Microsoft Graph Explorer is registered
           - Check API permissions are added
           - Verify admin consent status
        
        4. **Wait for Propagation**
           - After granting consent, wait 5-15 minutes
           - Azure AD can take time to propagate permissions
        
        5. **Contact Support**
           - If issues persist, contact Azure support
           - Provide error messages shown above
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