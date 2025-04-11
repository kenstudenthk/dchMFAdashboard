# graph_helper.py
import requests
import pandas as pd
from datetime import datetime
from typing import Optional, Dict, Any, List

class GraphAPI:
    def __init__(self, token: str):
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def get_user_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """Get MFA status for a user"""
        url = f"https://graph.microsoft.com/beta/users/{user_id}/authentication/requirements"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def get_user_licenses(self, user_id: str) -> List[str]:
        """Get user's licenses"""
        url = f"https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails"
        response = requests.get(url, headers=self.headers)
        licenses = response.json().get('value', [])
        
        license_names = []
        for license in licenses:
            sku_part_number = license.get('skuPartNumber', '')
            if 'ENTERPRISEPACK' in sku_part_number:
                license_names.append('Office365 E3')
            elif 'STANDARDPACK' in sku_part_number:
                license_names.append('Office365 E1')
            elif 'EMS' in sku_part_number:
                license_names.append('EMS E3')
            elif 'EMSPREMIUM' in sku_part_number:
                license_names.append('EMS E5')
            elif 'Win10_VDA_E3' in sku_part_number:
                license_names.append('Windows 10/11 Enterprise E3')
        
        return license_names

    def get_users_report(self, limit: int = 100, skip: int = 0) -> pd.DataFrame:
        """Get users report with MFA and license status"""
        url = f"https://graph.microsoft.com/v1.0/users?$top={limit}&$skip={skip}&$select=id,displayName,userPrincipalName,mail,createdDateTime,signInActivity"
        response = requests.get(url, headers=self.headers)
        users = response.json().get('value', [])
        
        user_data = []
        for user in users:
            # Get MFA status
            mfa_status = self.get_user_mfa_status(user['id'])
            mfa_enabled = not (mfa_status.get('mfa', {}).get('state') == 'disabled')
            
            # Get licenses
            licenses = self.get_user_licenses(user['id'])
            
            # Get last sign-in
            sign_in_activity = user.get('signInActivity', {})
            last_sign_in = sign_in_activity.get('lastSignInDateTime', '')
            
            user_data.append({
                'Name': user.get('displayName', ''),
                'Mail': user.get('mail', ''),
                'UPN': user.get('userPrincipalName', ''),
                'Licenses': ', '.join(licenses) if licenses else '-',
                'Creation Date': user.get('createdDateTime', ''),
                'MFA Enabled': mfa_enabled,
                'Last Interactive SignIn': last_sign_in
            })
        
        return pd.DataFrame(user_data)