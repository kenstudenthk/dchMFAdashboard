# Imports
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import time
import traceback
from typing import Optional
from threading import Thread
import queue
import json
from auth import GraphAuth, init_auth, check_auth
from mfa_status import get_mfa_status

# Streamlit config
st.set_page_config(
    page_title="MFA Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Global functions
def init_session_state():
    """Initialize session state variables"""
    defaults = {
        'job_running': False,
        'processed_users': [],
        'error_users': [],
        'current_batch': 0,
        'progress': 0,
        'status_message': "",
        'processing_status': False,
        'processing': False,
        'authenticated': False,
        'token': None,
        'processed_df': None,
        'num_users': 100,
        'data_loaded': False,
        'df': None
    }
    
    for key, default_value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

def save_progress_to_file():
    """Save progress to a file"""
    progress_data = {
        'processed_users': st.session_state.get('processed_users', []),
        'error_users': st.session_state.get('error_users', []),
        'current_batch': st.session_state.get('current_batch', 0),
        'progress': st.session_state.get('progress', 0)
    }
    
    with open('.streamlit/progress.json', 'w') as f:
        json.dump(progress_data, f)

def load_progress_from_file():
    """Load progress from file"""
    try:
        with open('.streamlit/progress.json', 'r') as f:
            progress_data = json.load(f)
            st.session_state.processed_users = progress_data['processed_users']
            st.session_state.error_users = progress_data['error_users']
            st.session_state.current_batch = progress_data['current_batch']
            st.session_state.progress = progress_data['progress']
    except FileNotFoundError:
        pass

@st.cache_data(ttl=3600)
def get_mfa_status_cached(token: str, limit: int, skip: int = 0):
    """Cached version of MFA status check"""
    try:
        return get_mfa_status(token, limit, skip)
    except Exception as e:
        st.error(f"Error in cached MFA status check: {str(e)}")
        return None
class UserAnalyzer:
    def __init__(self):
        self.init_session_state()

    def init_session_state(self):
        """Initialize session state variables specific to UserAnalyzer"""
        defaults = {
            'processed_df': pd.DataFrame(),
            'data_loaded': False,
            'num_users': 100
        }
        
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value

    def analyze_users(self):
        if st.button("Process All Users (Batch)"):
            total_users = st.session_state.get('num_users', 100)
            self.process_users_in_batches(total_users)

    def render_data_collection_tab(self):
        """Process users in batches with background processing"""
    try:
        # Initialize states
        st.session_state.processing = True
        st.session_state.job_running = True
        st.session_state.progress = 0
        st.session_state.current_batch = 0
        st.session_state.processed_df = pd.DataFrame()

        # Create progress indicators
        progress_container = st.empty()
        status_container = st.empty()
        data_container = st.empty()
        
        # Start background processing
        thread = Thread(target=self.background_processing, args=(total_users, batch_size))
        thread.daemon = True
        thread.start()
        
        # Update UI while processing
        while st.session_state.job_running:
            # Update progress bar
            progress_container.progress(st.session_state.progress)
            current_batch = st.session_state.current_batch
            status_container.text(f"Processing batch {current_batch}... ({len(st.session_state.processed_df)} users processed)")
            
            # Update data display
            if not st.session_state.processed_df.empty:
                df = st.session_state.processed_df.copy()
                st.session_state.df = df
                st.session_state.data_loaded = True
                
                if current_batch % 2 == 0:
                    with data_container.container():
                        st.markdown("### Current Results")
                        self.display_metrics_and_charts(df)
                        st.dataframe(df)
            
            time.sleep(1)
        
        # Final updates
        progress_container.progress(1.0)
        status_container.success(f"Processing complete! Processed {len(st.session_state.processed_df)} users")
        
        if not st.session_state.processed_df.empty:
            self.offer_download(st.session_state.processed_df)
        
    except Exception as e:
        st.error(f"Error during batch processing: {str(e)}")
        st.error(traceback.format_exc())
    finally:
        st.session_state.processing = False
        st.session_state.job_running = False

    def process_users(self, num_users: int):
        """Process a specific number of users"""
        try:
            st.session_state.processing = True
            batch_df = get_mfa_status_cached(st.session_state.token, num_users, 0)
            
            if batch_df is not None and not batch_df.empty:
                st.session_state.df = batch_df
                st.session_state.data_loaded = True
                self.display_metrics_and_charts(batch_df)
                st.dataframe(batch_df)
                
        except Exception as e:
            st.error(f"Error processing users: {str(e)}")
        finally:
            st.session_state.processing = False

    def process_users_in_batches(self, total_users: int, batch_size: int = 500):
        """Process users in batches with background processing"""
        try:
            # Initialize states
            st.session_state.processing = True
            st.session_state.job_running = True
            st.session_state.progress = 0
            st.session_state.current_batch = 0
            st.session_state.processed_df = pd.DataFrame()

            # Create progress indicators
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Start background processing
            thread = Thread(target=self.background_processing, args=(total_users, batch_size))
            thread.daemon = True
            thread.start()
            
            # Update UI while processing
            while st.session_state.job_running:
                progress_bar.progress(st.session_state.progress)
                current_batch = st.session_state.current_batch
                status_text.text(f"Processing batch {current_batch}...")
                
                if not st.session_state.processed_df.empty:
                    df = st.session_state.processed_df.copy()
                    st.session_state.df = df
                    st.session_state.data_loaded = True
                    
                    if current_batch % 2 == 0:
                        st.markdown("## Interim Analysis Results")
                        self.display_metrics_and_charts(df)
                        st.markdown("## Interim Data")
                        st.dataframe(df)
                
                time.sleep(1)
            
            # Final updates
            status_text.text("Processing complete!")
            progress_bar.progress(1.0)
            
            if not st.session_state.processed_df.empty:
                st.success(f"Successfully processed {len(st.session_state.processed_df)} users!")
                self.offer_download(st.session_state.processed_df)
            
        except Exception as e:
            st.error(f"Error during batch processing: {str(e)}")
            st.error(traceback.format_exc())
        finally:
            st.session_state.processing = False
            st.session_state.job_running = False

    def background_processing(self, total_users: int, batch_size: int):
     """Background processing function"""
    try:
        num_batches = (total_users + batch_size - 1) // batch_size
        processed_count = 0
        
        for batch_num in range(num_batches):
            if not st.session_state.job_running:
                break
                
            start_idx = batch_num * batch_size
            try:
                batch_df = get_mfa_status_cached(
                    token=st.session_state.token,
                    limit=batch_size,
                    skip=start_idx
                )
                
                if batch_df is not None and not batch_df.empty:
                    if st.session_state.processed_df.empty:
                        st.session_state.processed_df = batch_df
                    else:
                        st.session_state.processed_df = pd.concat(
                            [st.session_state.processed_df, batch_df], 
                            ignore_index=True
                        )
                    processed_count += len(batch_df)
                
                # Update progress
                st.session_state.progress = min((batch_num + 1) / num_batches, 1.0)
                st.session_state.current_batch = batch_num + 1
                
                if batch_num % 5 == 0:
                    save_progress_to_file()
                
                # Add delay to prevent API throttling
                time.sleep(0.5)
                
            except Exception as e:
                st.session_state.error_users.append({
                    'batch': batch_num,
                    'start_idx': start_idx,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
                # Continue processing despite errors
                continue
                
    except Exception as e:
        st.error(f"Fatal error in background processing: {str(e)}")
    finally:
        st.session_state.job_running = False
        save_progress_to_file()

    def cancel_processing(self):
        """Cancel the processing job"""
        st.session_state.processed_count = 0
        st.session_state.mfa_data = []
        st.session_state.error_users = []
        st.session_state.processing = False
        st.session_state.job_running = False
        if 'processed_df' in st.session_state:
            del st.session_state.processed_df
        st.experimental_rerun()

    def offer_download(self, df: pd.DataFrame):
        """Offer download option for the data"""
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download Complete Data as CSV",
            data=csv,
            file_name="complete_mfa_status.csv",
            mime="text/csv"
        )

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

    def apply_filters(self, df):
        """Apply filters to the DataFrame"""
        try:
            if df is None or df.empty:
                return df

            available_columns = df.columns.tolist()
            st.write("Available columns for filtering:", available_columns)

            cols = st.columns(3)
            filters = {}
            
            if 'userPrincipalName' in available_columns:
                with cols[0]:
                    email_filter = st.text_input('Filter by Email')
                    if email_filter:
                        filters['userPrincipalName'] = email_filter

            if 'displayName' in available_columns:
                with cols[1]:
                    name_filter = st.text_input('Filter by Name')
                    if name_filter:
                        filters['displayName'] = name_filter

            filtered_df = df.copy()
            for column, value in filters.items():
                if value:
                    filtered_df = filtered_df[filtered_df[column].str.contains(value, case=False, na=False)]

            return filtered_df

        except Exception as e:
            st.error(f"Error applying filters: {str(e)}")
            return df

    def display_metrics_and_charts(self, df):
        """Display metrics and charts"""
        try:
            if df is None or df.empty:
                st.warning("No data available to display metrics and charts")
                return

            st.write("Available columns:", df.columns.tolist())

            total_users = len(df)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Users", total_users)
            
            with col2:
                if 'assignedLicenses' in df.columns:
                    licensed_users = df['assignedLicenses'].apply(lambda x: len(x) > 0 if isinstance(x, list) else False).sum()
                    st.metric("Licensed Users", licensed_users)
            
            with col3:
                if 'signInActivity' in df.columns:
                    active_users = df['signInActivity'].apply(
                        lambda x: x.get('lastSignInDateTime') is not None if isinstance(x, dict) else False
                    ).sum()
                    st.metric("Active Users", active_users)

            self.create_mfa_distribution_chart(df)
            self.create_license_distribution_chart(df)

        except Exception as e:
            st.error(f"Error displaying metrics and charts: {str(e)}")

    def create_mfa_distribution_chart(self, df: pd.DataFrame):
        """Create MFA distribution chart"""
        try:
            st.markdown("### MFA Status Distribution")
            if 'MFAStatus' in df.columns:
                mfa_counts = df['MFAStatus'].value_counts()
                st.bar_chart(mfa_counts)
            else:
                st.warning("MFA Status information not available")
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
        self.offer_download(df)

    def handle_logout(self):
        """Handle the logout process"""
        auth = init_auth()
        if auth.logout():
            st.session_state.authenticated = False
            if 'token' in st.session_state:
                del st.session_state.token
            st.success("Successfully logged out!")
            st.rerun()

class Dashboard:
    def __init__(self):
        init_session_state()
        self.setup_page()
        self.analyzer = UserAnalyzer()
        
    def setup_page(self):
        """Configure basic page settings"""
        # Add any additional page configuration here
        pass

    def handle_login(self):
        """Handle the login process"""
        auth = init_auth()
        
        # Get device code flow
        flow = auth.initiate_device_flow()
        if flow:
            st.markdown("### 🔐 Login Required")
            st.write("To continue, please follow these steps:")
            st.code(flow['message'])
            
            # Create columns for the QR code and instructions
            col1, col2 = st.columns([1, 2])
            
            with col1:
                # Display help text
                st.markdown("""
                1. Open the Microsoft Authenticator app
                2. Scan the code or enter the code manually
                3. Follow the prompts in the app
                """)
            
            # Wait for authentication with a timeout
            try:
                with st.spinner('Waiting for authentication...'):
                    result = auth.acquire_token_by_device_flow(flow)
                    if result:
                        st.session_state.authenticated = True
                        st.session_state.token = result['access_token']
                        st.success("✅ Successfully logged in!")
                        time.sleep(1)  # Give user time to see success message
                        st.rerun()
            except Exception as e:
                st.error(f"Authentication failed: {str(e)}")
                st.button("Try Again", on_click=self.handle_login)

    def render_sidebar(self):
        """Render the sidebar content"""
        with st.sidebar:
            st.image("https://via.placeholder.com/150", caption="MFA Checker")
            st.markdown("---")
            
            # Add refresh rate slider if authenticated
            if st.session_state.authenticated:
                st.markdown("### Settings")
                refresh_rate = st.slider(
                    "Refresh Rate (seconds)",
                    min_value=1,
                    max_value=60,
                    value=st.session_state.get('refresh_rate_value', 5)
                )
                st.session_state.refresh_rate_value = refresh_rate
                
                # Add logout button
                if st.button("🚪 Logout", use_container_width=True):
                    self.analyzer.handle_logout()

    def render_header(self):
        """Render the main header"""
        st.title("🔒 MFA Status Checker")
        
        # Add description
        st.markdown("""
        This dashboard helps you monitor and manage Multi-Factor Authentication (MFA) status
        for your organization's users. You can:
        
        - Check MFA status for individual users
        - Process users in batches
        - View detailed analytics
        - Export results to CSV
        """)
        st.markdown("---")

    def render_main_interface(self):
        """Render the main application interface"""
        self.render_sidebar()
        self.render_header()
        
        if not st.session_state.authenticated:
            self.handle_login()
            return
            
        # Main tabs
        tab1, tab2 = st.tabs(["📊 Data Collection", "📈 Analysis"])
        
        with tab1:
            self.analyzer.render_data_collection_tab()
            
        with tab2:
            self.analyzer.render_analysis_tab()

        # Add footer
        st.markdown("---")
        st.markdown(
            """
            <div style='text-align: center'>
                <p>MFA Status Checker Dashboard • Built with Streamlit</p>
            </div>
            """,
            unsafe_allow_html=True
        )

    def handle_error(self, error: Exception):
        """Handle application errors"""
        st.error("An error occurred in the application")
        
        # Create expander for error details
        with st.expander("Error Details"):
            st.error(f"Error: {str(error)}")
            st.code(traceback.format_exc())
            
        # Add reset button
        if st.button("🔄 Reset Application"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    def run(self):
        """Run the dashboard application"""
        try:
            # Check authentication status
            if not check_auth():
                st.session_state.authenticated = False
                
            # Render main interface
            self.render_main_interface()
            
        except Exception as e:
            self.handle_error(e)
            
        finally:
            # Cleanup if needed
            if st.session_state.get('processing', False):
                st.session_state.job_running = False

    def check_token_validity(self):
        """Check if the current token is valid"""
        if not st.session_state.get('token'):
            return False
            
        try:
            # Try to make a simple API call to verify token
            test_df = get_mfa_status_cached(st.session_state.token, 1, 0)
            return test_df is not None
        except Exception:
            return False

    def refresh_token_if_needed(self):
        """Refresh the token if it's expired"""
        if not self.check_token_validity():
            auth = init_auth()
            try:
                new_token = auth.acquire_token_silent()
                if new_token:
                    st.session_state.token = new_token['access_token']
                    return True
                else:
                    st.session_state.authenticated = False
                    return False
            except Exception:
                st.session_state.authenticated = False
                return False
        return True

# Add CSS styling
def load_css():
    st.markdown("""
        <style>
        /* Custom styling for the dashboard */
        .stApp {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        /* Header styling */
        .main-header {
            color: #1f77b4;
            padding-bottom: 20px;
        }
        
        /* Progress bar styling */
        .stProgress > div > div {
            background-color: #1f77b4;
        }
        
        /* Button styling */
        .stButton > button {
            width: 100%;
            border-radius: 5px;
            height: 3em;
            transition: all 0.3s ease;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        /* Metric styling */
        [data-testid="stMetricValue"] {
            font-size: 1.8rem;
            color: #1f77b4;
        }
        
        /* Table styling */
        .dataframe {
            font-size: 0.9em;
            border-collapse: collapse;
            margin: 25px 0;
            min-width: 400px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
        }
        
        /* Alert styling */
        .stAlert {
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 0.5rem;
        }
        </style>
    """, unsafe_allow_html=True)

def main():
    try:
        # Load custom CSS
        load_css()
        
        # Initialize and run the dashboard
        dashboard = Dashboard()
        
        # Add version info in sidebar footer
        with st.sidebar:
            st.markdown("---")
            st.markdown(
                """
                <div style='text-align: center; color: #888;'>
                    <small>Version 1.0.0</small><br>
                    <small>Last updated: April 2025</small>
                </div>
                """,
                unsafe_allow_html=True
            )
        
        # Run the dashboard
        dashboard.run()
        
    except Exception as e:
        st.error("Critical Error")
        with st.expander("Error Details"):
            st.error(f"Error: {str(e)}")
            st.code(traceback.format_exc())
        
        if st.button("🔄 Restart Application"):
            st.session_state.clear()
            st.experimental_rerun()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        st.warning("Application terminated by user")
    except Exception as e:
        st.error(f"Fatal error: {str(e)}")
        st.code(traceback.format_exc())