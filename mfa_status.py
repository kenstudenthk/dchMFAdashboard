# graph_helper.py
import requests
import pandas as pd
from datetime import datetime
import streamlit as st
from save_state import ENDPOINT

class GraphAPI:
    def __init__(self, token):
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def get_users_report(self, limit=100):
        """Get users report with MFA and license status"""
        try:
            # Get users
            url = f"{ENDPOINT}/users?$top={limit}&$select=id,displayName,userPrincipalName,mail,createdDateTime,signInActivity"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            users = response.json().get('value', [])
            
            user_data = []
            for user in users:
                # Get MFA status
                mfa_status = self.get_user_mfa_status(user['id'])
                
                # Get licenses
                licenses = self.get_user_licenses(user['id'])
                
                user_data.append({
                    'Display Name': user.get('displayName', ''),
                    'Email': user.get('mail', ''),
                    'UPN': user.get('userPrincipalName', ''),
                    'Created Date': user.get('createdDateTime', ''),
                    'MFA Enabled': mfa_status,
                    'Licenses': ', '.join(licenses) if licenses else '',
                    'Last Sign In': user.get('signInActivity', {}).get('lastSignInDateTime', '')
                })
            
            return pd.DataFrame(user_data)
        
        except Exception as e:
            st.error(f"Error getting users report: {str(e)}")
            return pd.DataFrame()

    def get_user_mfa_status(self, user_id):
        """Get MFA status for a user"""
        try:
            url = f"{ENDPOINT}/users/{user_id}/authentication/methods"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            methods = response.json().get('value', [])
            return any(method.get('@odata.type', '').endswith('MicrosoftAuthenticatorAuthenticationMethod') 
                      for method in methods)
        except:
            return False

    def get_user_licenses(self, user_id):
        """Get user's licenses"""
        try:
            url = f"{ENDPOINT}/users/{user_id}/licenseDetails"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            licenses = response.json().get('value', [])
            return [license.get('skuPartNumber', '') for license in licenses]
        except:
            return []