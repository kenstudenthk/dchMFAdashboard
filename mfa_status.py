import streamlit as st
import pandas as pd
import requests
import time
import traceback
from typing import Optional, Dict, List
from datetime import datetime

# License mapping dictionary
LICENSE_MAPPING = {
    "c42b9cae-ea4f-4ab7-9717-81576235ccac": "DevTools E5",
    "f30db892-07e9-47e9-837c-80727f46fd3d": "MICROSOFT FLOW FREE",
    "f245ecc8-75af-4f8e-b61f-27d8114de5f3": "Standard User",
    "2b9c8e7c-319c-43a2-a2a0-48c5c6161de7": "Basic Employee",
    "be21a6b7-87c5-4f2b-b5a3-a4a89608c5a5": "Exchange Online Plan 1",
    "314c4481-f395-4525-be8b-2ec4bb1e9d91": "Office 365 Web Apps",
    "09015f9f-377f-4538-bbb5-f75ceb09358a": "BEYONDTRUST PRIVILEGE REMOTE ACCESS REPRESENTATIVE ACCOUNT",
    "c5928f49-12ba-48f7-ada3-0d743a3601d5": "Microsoft Power Automate Free",
    "06ebc4ee-1bb5-47dd-8120-11324bc54e06": "Microsoft Context IQ",
    "726a0894-2c77-4d65-99da-9775ef05aad1": "Microsoft Dynamics 365 Export to Data Lake",
    "338148b6-ebd6-4209-a9db-59c6a9d235a2": "Microsoft Dynamics 365 Human Resources Self Service",
    "1f2f344a-700d-42c9-9427-5cea1d5d7ba6": "Microsoft Stream Trial",
    "bea13e0c-3828-4daa-a392-28af7ff61a0f": "MICROSOFT TEAM EXPLORATORY",
    "4b9405b0-7788-4568-add1-99614e613b69": "PHONESYSTEM_VIRTUALUSER",
    "3b555118-da6a-4418-894f-7df1e2096870": "O365_BUSINESS_ESSENTIALS",
    "a403ebcc-fae0-4ca2-8c8c-7a907fd6c235": "POWER BI (FREE)",
    "602f1d49-dd68-43dd-9649-fba2a5b7c12c": "SB ONLINE ENTERPRISE ESSENTIALS",
    "c42b9cae-ea4f-4ab7-9717-81576235ccac": "VISIOCLIENT",
    "f30db892-07e9-47e9-837c-80727f46fd3d": "WINDOWS BUSINESS",
    "f245ecc8-75af-4f8e-b61f-27d8114de5f3": "WINDOWS ENTERPRISE E3",
    "2b9c8e7c-319c-43a2-a2a0-48c5c6161de7": "WINDOWS ENTERPRISE E5",
    "be21a6b7-87c5-4f2b-b5a3-a4a89608c5a5": "WINDEFATP",
    "314c4481-f395-4525-be8b-2ec4bb1e9d91": "ENTERPRISEPREMIUM",
    "09015f9f-377f-4538-bbb5-f75ceb09358a": "ENTERPRISEPACK",
    "c5928f49-12ba-48f7-ada3-0d743a3601d5": "DYN365_ENTERPRISE_PLAN1",
    "06ebc4ee-1bb5-47dd-8120-11324bc54e06": "DYN365_ENTERPRISE_CUSTOMER_SERVICE",
    "726a0894-2c77-4d65-99da-9775ef05aad1": "DYN365_FINANCIALS_BUSINESS_SKU",
    "338148b6-ebd6-4209-a9db-59c6a9d235a2": "FLOW_FREE",
    "1f2f344a-700d-42c9-9427-5cea1d5d7ba6": "POWER_BI_PRO",
    "bea13e0c-3828-4daa-a392-28af7ff61a0f": "POWER_BI_STANDARD",
    "4b9405b0-7788-4568-add1-99614e613b69": "PROJECTPROFESSIONAL",
    "3b555118-da6a-4418-894f-7df1e2096870": "PROJECTONLINE_PLAN_1",
    "a403ebcc-fae0-4ca2-8c8c-7a907fd6c235": "PROJECTONLINE_PLAN_2"
}

def process_user_details(user: Dict, headers: Dict) -> Dict:
    """Process individual user details including licenses and auth methods"""
    # Get license details
    license_response = requests.get(
        f'https://graph.microsoft.com/v1.0/users/{user["id"]}/licenseDetails',
        headers=headers
    )
    
    # Get authentication methods
    auth_methods_response = requests.get(
        f'https://graph.microsoft.com/v1.0/users/{user["id"]}/authentication/methods',
        headers=headers
    )
    
    # Process licenses
    licenses = []
    if license_response.status_code == 200:
        license_details = license_response.json().get('value', [])
        for license in license_details:
            sku_id = license.get('skuId', '')
            license_name = LICENSE_MAPPING.get(sku_id, f'Unknown License ({sku_id})')
            licenses.append(license_name)
    
    # Process authentication methods
    mfa_status = "None"
    auth_methods = []
    if auth_methods_response.status_code == 200:
        methods = auth_methods_response.json().get('value', [])
        auth_methods = [m.get('methodType', '') for m in methods]
        if any(method != 'password' for method in auth_methods):
            mfa_status = "Enabled"
        elif auth_methods:
            mfa_status = "Disabled"
    
    return {
        'DisplayName': user.get('displayName', 'None'),
        'UserPrincipalName': user.get('userPrincipalName', 'None'),
        'Licenses': ', '.join(licenses) if licenses else 'None',
        'MFAStatus': mfa_status,
        'AuthMethods': ', '.join(auth_methods) if auth_methods else 'None',
        'CreationDate': user.get('createdDateTime', 'None'),
        'LastInteractiveSignIn': user.get('signInActivity', {}).get('lastSignInDateTime', 'None'),
        'LastNonInteractiveSignIn': user.get('signInActivity', {}).get('lastNonInteractiveSignInDateTime', 'None')
    }

def process_user_batch(headers, users_batch, processed_count, total_limit):
    """Process a batch of users to get their MFA status"""
    batch_data = []
    batch_errors = []
    
    for user in users_batch:
        try:
            # Get MFA method information
            mfa_methods_url = f"https://graph.microsoft.com/v1.0/users/{user['id']}/authentication/methods"
            mfa_response = requests.get(mfa_methods_url, headers=headers)
            
            if mfa_response.status_code != 200:
                batch_errors.append({
                    'UserPrincipalName': user.get('userPrincipalName', 'None'),
                    'Error': f"MFA API Error: {mfa_response.status_code}"
                })
                continue
                
            mfa_methods = mfa_response.json().get('value', [])
            
            # Get sign in activity details
            sign_in_activity = user.get('signInActivity', {})
            
            # Process user data
            user_data = {
                'UserPrincipalName': user.get('userPrincipalName', ''),
                'DisplayName': user.get('displayName', ''),
                'CreatedDateTime': user.get('createdDateTime', ''),
                'LastSignIn': sign_in_activity.get('lastSignInDateTime', ''),
                'LastInteractiveSignIn': sign_in_activity.get('lastInteractiveSignInDateTime', ''),
                'LastNonInteractiveSignIn': sign_in_activity.get('lastNonInteractiveSignInDateTime', ''),
                'MFAMethods': [method.get('@odata.type', '').split('.')[-1] for method in mfa_methods],
                'MFACount': len(mfa_methods),
                'HasMFA': len(mfa_methods) > 0
            }
            
            batch_data.append(user_data)
            processed_count += 1
            
            # Add small delay to prevent throttling
            time.sleep(0.1)
            
        except Exception as e:
            batch_errors.append({
                'UserPrincipalName': user.get('userPrincipalName', 'None'),
                'Error': str(e)
            })
            processed_count += 1
            
    return batch_data, batch_errors, processed_count
def get_mfa_status(token: str, limit: int, skip: int = 0) -> Optional[pd.DataFrame]:
    try:
        st.write(f"Starting MFA status check (Batch: Skip {skip}, Limit {limit})...")
        
        # Initialize variables
        headers = {'Authorization': f'Bearer {token}'}
        BATCH_SIZE = 40
        mfa_data = []
        error_users = []
        
        # Setup progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Get total user count
        count_response = requests.get(
            'https://graph.microsoft.com/v1.0/users/$count',
            headers={**headers, 'ConsistencyLevel': 'eventual'}
        )
        
        if count_response.status_code != 200:
            st.error(f"Failed to get user count: {count_response.status_code}")
            return None
            
        total_users = int(count_response.text)
        actual_limit = min(limit, total_users - skip)
        processed_count = 0
        
        # Process users in batches - Fixed the f-string here
        next_link = f'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,createdDateTime,signInActivity,assignedLicenses&$top={BATCH_SIZE}'
        
        while next_link and processed_count < actual_limit:
            users_response = requests.get(next_link, headers=headers)
            
            if users_response.status_code != 200:
                st.error(f"Users API Error: {users_response.status_code} - {users_response.text}")
                return None
            
            response_data = users_response.json()
            users_data = response_data.get('value', [])
            
            # Process current batch
            remaining = actual_limit - processed_count
            users_to_process = min(len(users_data), remaining)
            current_batch = users_data[:users_to_process]
            
            batch_start = processed_count + 1
            batch_end = processed_count + users_to_process
            st.info(f"Processing users {batch_start} to {batch_end}")
            
            # Process batch
            batch_data, batch_errors, processed_count = process_user_batch(
                headers, current_batch, processed_count, actual_limit
            )
            
            mfa_data.extend(batch_data)
            error_users.extend(batch_errors)
            
            # Update progress
            progress = processed_count / actual_limit
            progress_bar.progress(progress)
            status_text.text(f"Processing user {processed_count} of {actual_limit}")
            
            # Get next batch link
            next_link = response_data.get('@odata.nextLink')
            if processed_count >= actual_limit:
                break
        
        # Process results
        if mfa_data:
            status_text.empty()
            df = pd.DataFrame(mfa_data)
            
            # Debug information
            st.write(f"Data shape: {df.shape}")
            st.write("Columns in DataFrame:", df.columns.tolist())
            st.write("Sample of data:")
            st.write(df.head())
            
            st.success(f"Successfully processed {len(mfa_data)} users!")
            
            if error_users:
                st.warning(f"Failed to process {len(error_users)} users. Check logs for details.")
            
            return df
        else:
            st.warning("No data was collected")
            return None
        
    except Exception as e:
        st.error(f"MFA status error: {str(e)}")
        st.code(traceback.format_exc())
        return None