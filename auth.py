# auth.py
import msal
import streamlit as st
from save_state import CLIENT_ID, TENANT_ID, SCOPES
import time

class GraphAuth:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.authority = f"https://login.microsoftonline.com/{TENANT_ID}"
        
        self.app = msal.PublicClientApplication(
            client_id=self.client_id,
            authority=self.authority
        )

    def get_device_flow(self):
        """Start device code flow authentication"""
        try:
            # Simple device flow initialization with just scopes
            flow = self.app.initiate_device_flow(scopes=SCOPES)
            
            if "user_code" not in flow:
                error_msg = flow.get('error_description', 'Unknown error in device flow')
                raise ValueError(f"Could not initiate device flow: {error_msg}")
                
            return flow
            
        except Exception as e:
            st.error(f"Error initiating device flow: {str(e)}")
            return None

    def process_device_flow(self, flow, timeout=300):  # 5 minutes timeout
        """Process device flow authentication with timeout"""
        try:
            if not flow:
                return None
                
            # Store start time
            start_time = time.time()
            
            while True:
                # Check if timeout exceeded
                if time.time() - start_time > timeout:
                    st.error("Authentication timeout. Please try again.")
                    return None

                try:
                    result = self.app.acquire_token_by_device_flow(
                        flow,
                        timeout=5  # 5 seconds polling interval
                    )
                    
                    if result and "access_token" in result:
                        return result
                        
                except Exception as e:
                    if "timeout" not in str(e).lower():
                        raise e
                    # Continue polling if it's just a timeout
                    continue

        except Exception as e:
            st.error(f"Error in device flow process: {str(e)}")
            return None

def init_auth():
    return GraphAuth()

def check_auth():
    return st.session_state.get('authenticated', False)