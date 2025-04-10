import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import time
import traceback
from typing import Optional
from auth import GraphAuth, init_auth, check_auth  # Added check_auth here
from mfa_status import get_mfa_status

# Set page config at the very top of dashboard.py
st.set_page_config(
    page_title="MFA Status Check",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'processed_count' not in st.session_state:
    st.session_state.processed_count = 0
    st.session_state.mfa_data = []
    st.session_state.error_users = []

class UserAnalyzer:
    def render_data_collection_tab(self):
      """Render the Data Collection tab"""
      st.header("📊 Data Collection")
      st.markdown("---")
    
      token = st.text_input("Enter token", type="password")
      num_users = st.number_input(
        "Number of users to process",
        min_value=1,
        max_value=500,
        value=st.session_state.get('num_users', 100),
        step=10
    )
      st.session_state.num_users = num_users
    
    # Modified column layout to include cancel button
      col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
    
      with col1:
        if st.button("🔍 Process Users", key="process_users", use_container_width=True):
            self.process_users(num_users)
    
      with col2:
        if st.button("👥 Process All Users (Batch)", key="process_all_users", use_container_width=True):
            self.process_users_in_batches(13000, batch_size=500)
    
      with col3:
        if st.button("Logout", key="logout_button", use_container_width=True):
            self.handle_logout()
    
      with col4:
        # Add cancel button
        if st.button("❌ Cancel", key="cancel_processing", use_container_width=True):
            st.session_state.processed_count = 0
            st.session_state.mfa_data = []
            st.session_state.error_users = []
            st.session_state.processing = False
            st.session_state.processing_status = False
            if 'processed_df' in st.session_state:
                del st.session_state.processed_df
            st.experimental_rerun()

    # Show processing status if active
      if st.session_state.processing:
        st.info("Processing in progress... Use the Cancel button to stop.")
    def process_users_in_batches(self, total_users: int, batch_size: int = 500):
        """Process users in batches"""
        try:
            # Initialize processing state
            st.session_state.processing_status = True
            st.session_state.processing = True
            
            # Initialize progress tracking
            if 'processed_df' not in st.session_state:
                st.session_state.processed_df = pd.DataFrame()
            
            # Calculate number of batches
            num_batches = (total_users + batch_size - 1) // batch_size
            
            # Create progress bar
            progress_text = "Processing users in batches..."
            my_bar = st.progress(0)
            status_text = st.empty()
            
            # Process each batch
            for batch_num in range(num_batches):
                # Check if processing was cancelled
                if st.session_state.get('processing', True):
                    # Calculate batch indices
                    start_idx = batch_num * batch_size
                    end_idx = min(start_idx + batch_size, total_users)
                    
                    # Update status
                    status_text.text(f"Processing batch {batch_num + 1}/{num_batches} (Users {start_idx + 1} to {end_idx})")
                    
                    # Get batch data
                    batch_df = get_mfa_status(st.session_state.token, batch_size, start_idx)
                    
                    if batch_df is not None and not batch_df.empty:
                        # Append batch results to main DataFrame
                        st.session_state.processed_df = pd.concat([st.session_state.processed_df, batch_df], ignore_index=True)
                        
                        # Update progress
                        progress = (batch_num + 1) / num_batches
                        my_bar.progress(progress)
                        
                        # Display interim results
                        if (batch_num + 1) % 2 == 0 or batch_num == num_batches - 1:
                            st.session_state.df = st.session_state.processed_df.copy()
                            st.session_state.data_loaded = True
                            
                            # Display interim analysis
                            st.markdown("## Interim Analysis Results")
                            self.display_metrics_and_charts(st.session_state.df)
                            
                            # Display interim data table
                            st.markdown("## Interim Data")
                            st.dataframe(st.session_state.df)
                    
                    # Add delay to prevent API rate limiting
                    time.sleep(1)
                else:
                    st.warning("Processing cancelled by user")
                    return
            
            # Final update
            status_text.text("Processing complete!")
            my_bar.progress(1.0)
            
            # Display final results
            st.success(f"Successfully processed {len(st.session_state.processed_df)} users!")
            
            # Add download option for complete dataset
            csv = st.session_state.processed_df.to_csv(index=False)
            st.download_button(
                label="Download Complete Data as CSV",
                data=csv,
                file_name="complete_mfa_status.csv",
                mime="text/csv"
            )
            
        except Exception as e:
            st.error(f"Error during batch processing: {str(e)}")
            st.error(traceback.format_exc())
        
        finally:
            # Reset processing flags
            st.session_state.processing_status = False
            st.session_state.processing = False
            
            # Clear interim data
            if 'processed_df' in st.session_state:
                del st.session_state.processed_df

    def render_analysis_tab(self):
        """Render the Analysis tab"""
        st.header("📈 Analysis")
        
        if not self.check_data_loaded():
            return
        
        try:
            df = st.session_state.df.copy()
            if df.empty:
                st.warning("No data available for analysis")
                return
            
            df_filtered = self.apply_filters(df)
            self.display_metrics_and_charts(df_filtered)
            self.display_data_table(df_filtered)
            
        except Exception as e:
            st.error(f"Error in analysis: {str(e)}")
            st.error(traceback.format_exc())

    def check_data_loaded(self) -> bool:
        """Check if data is loaded and available"""
        if not st.session_state.get('data_loaded', False) or st.session_state.get('df') is None:
            st.warning("Please load data in the Data Collection tab first")
            return False
        return True

    def apply_filters(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply sidebar filters to the dataframe"""
        with st.sidebar:
            st.markdown("## Filters")
            try:
                # Check if required columns exist
                if 'MFAStatus' not in df.columns or 'Licenses' not in df.columns:
                    st.warning("Required columns not found in data")
                    return df
                    
                mfa_options = sorted(df['MFAStatus'].dropna().unique().tolist())
                license_options = sorted(df['Licenses'].dropna().unique().tolist())
            
                selected_mfa = st.multiselect(
                    "MFA Status",
                    options=mfa_options,
                    default=mfa_options
                )
            
                selected_licenses = st.multiselect(
                    "License Type",
                    options=license_options,
                    default=license_options
                )
            
                if selected_mfa and selected_licenses:
                    return df[
                        (df['MFAStatus'].isin(selected_mfa)) &
                        (df['Licenses'].isin(selected_licenses))
                    ]
                return df
            
            except Exception as e:
                st.error(f"Error creating filters: {str(e)}")
                return df

    def display_metrics_and_charts(self, df: pd.DataFrame):
        """Display metrics and visualization charts"""
        try:
            col1, col2, col3 = st.columns(3)
            total_users = len(df)
            
            with col1:
                st.metric("Total Users", total_users)
            
            with col2:
                mfa_enabled = len(df[df['MFAStatus'] == 'Enabled'])
                mfa_pct = (mfa_enabled/total_users*100) if total_users > 0 else 0
                st.metric("MFA Enabled", f"{mfa_enabled} ({mfa_pct:.1f}%)")
            
            with col3:
                mfa_disabled = len(df[df['MFAStatus'] == 'Disabled'])
                disabled_pct = (mfa_disabled/total_users*100) if total_users > 0 else 0
                st.metric("MFA Disabled", f"{mfa_disabled} ({disabled_pct:.1f}%)")

            st.markdown("## Data Visualization")
            viz_col1, viz_col2 = st.columns(2)
            
            with viz_col1:
                self.create_mfa_distribution_chart(df)
            
            with viz_col2:
                self.create_license_distribution_chart(df)

        except Exception as e:
            st.error(f"Error displaying metrics and charts: {str(e)}")

    def create_mfa_distribution_chart(self, df: pd.DataFrame):
        """Create MFA distribution chart"""
        try:
            st.markdown("### MFA Status Distribution")
            mfa_counts = df['MFAStatus'].value_counts()
            st.bar_chart(mfa_counts)
        except Exception as e:
            st.error(f"Error creating MFA distribution chart: {str(e)}")

    def create_license_distribution_chart(self, df: pd.DataFrame):
        """Create license distribution chart"""
        try:
            st.markdown("### License Distribution")
            if 'Licenses' in df.columns:
                license_counts = df['Licenses'].value_counts()
                st.bar_chart(license_counts)
            else:
                st.warning("License information not available")
        except Exception as e:
            st.error(f"Error creating license distribution chart: {str(e)}")

    def display_data_table(self, df: pd.DataFrame):
        """Display the data table with download option"""
        st.markdown("## Detailed Data")
        st.dataframe(df)
        
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download Filtered Data as CSV",
            data=csv,
            file_name="filtered_mfa_status.csv",
            mime="text/csv"
        )
    def handle_logout(self):
        """Handle the logout process"""
        auth = init_auth()
        if auth.logout():
            st.session_state.authenticated = False
            if 'token' in st.session_state:
                del st.session_state.token
            st.success("Successfully logged out!")
            st.rerun()
# Add the Dashboard class
class Dashboard:
    def __init__(self):
        self.setup_page()
        self.init_session_state()
        self.analyzer = UserAnalyzer()
        
    def setup_page(self):
        """Configure basic page settings"""
        pass
    
    def init_session_state(self):
        """Initialize session state variables"""
        defaults = {
            'authenticated': False,
            'data_loaded': False,
            'processing': False,
            'processing_status': False,
            'refresh_rate_value': 5,
            'df': None,
            'token': None
        }
        
        for key, default_value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = default_value

    def handle_login(self):
        """Handle the login process"""
        auth = init_auth()
        
        # Get device code flow
        flow = auth.initiate_device_flow()
        if flow:
            st.markdown("### 🔐 Login Required")
            st.write("To continue, please follow these steps:")
            st.code(flow['message'])
            
            # Wait for authentication
            result = auth.acquire_token_by_device_flow(flow)
            if result:
                st.session_state.authenticated = True
                st.session_state.token = result['access_token']
                st.success("✅ Successfully logged in!")
                st.rerun()

    def render_main_interface(self):
        """Render the main application interface"""
        # Sidebar
        with st.sidebar:
            st.image("https://via.placeholder.com/150", caption="MFA Checker")
            st.markdown("---")
            
        # Main content
        st.title("🔒 MFA Status Checker")
        
        if not st.session_state.authenticated:
            self.handle_login()
            return
            
        # Main tabs
        tab1, tab2 = st.tabs(["Data Collection", "Analysis"])
        
        with tab1:
            self.analyzer.render_data_collection_tab()
            
        with tab2:
            self.analyzer.render_analysis_tab()

    def run(self):
        """Run the dashboard application"""
        try:
            if not check_auth():
                st.session_state.authenticated = False
            self.render_main_interface()
            
        except Exception as e:
            st.error(f"Application error: {str(e)}")
            if st.button("Reset Application"):
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()
                   

# Add the main execution
if __name__ == "__main__":
    dashboard = Dashboard()
    dashboard.run()
                
