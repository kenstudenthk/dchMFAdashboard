# Keep all your imports at the top
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

# This must be the first Streamlit command
st.set_page_config(
    page_title="MFA Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
        'num_users': 100
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
def get_mfa_status_cached(self, token: str, limit: int, skip: int = 0):
    """Cached version of MFA status check"""
    try:
        return get_mfa_status(token, limit, skip)
    except Exception as e:
        st.error(f"Error in cached MFA status check: {str(e)}")
        return None
# Your current process_batch function
def process_batch(users, batch_size=100):
    """Process a batch of users in the background"""
    total_users = len(users)
    
    for i in range(0, total_users, batch_size):
        if not st.session_state.job_running:
            break
            
        batch = users[i:i+batch_size]
        for user in batch:  # Processes one user at a time
            try:
                result = get_mfa_status_cached(user)
                if result:
                    st.session_state.processed_users.append(result)
            except Exception as e:
                st.session_state.error_users.append({
                    'user': user,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        # Update progress
        st.session_state.progress = min((i + batch_size) / total_users, 1.0)
        st.session_state.current_batch = i // batch_size
        
        if i % (batch_size * 5) == 0:
            save_progress_to_file()
        
        time.sleep(0.1)

def process_users_in_batches(self, total_users: int, batch_size: int = 500):
    """Process users in batches with background processing"""
    try:
        # Initialize processing state
        st.session_state.processing_status = True
        st.session_state.processing = True
        st.session_state.job_running = True
        
        # Initialize processed_df as an empty DataFrame, not None
        if 'processed_df' not in st.session_state or st.session_state.processed_df is None:
            st.session_state.processed_df = pd.DataFrame()
        
        # Now you can safely check if it's empty
        if 'processed_df' in st.session_state and not st.session_state.processed_df.empty:
            # Your code for handling existing data
            pass

        progress_text = "Processing users in batches..."
        my_bar = st.progress(0)
        status_text = st.empty()
        
        # Start background processing
        thread = threading.Thread(target=self.background_processing)
        thread.start()
        
    except Exception as e:
        st.error(f"Error during batch processing: {str(e)}")
        st.session_state.job_running = False

def background_processing(self):
   try:
         total_users = st.session_state.num_users
         batch_size = 500  # or whatever batch size you want to use
         num_batches = (total_users + batch_size - 1) // batch_size
        
         for batch_num in range(num_batches):
            if not st.session_state.job_running:
                break
                
            start_idx = batch_num * batch_size
            batch_df = self.get_mfa_status_cached(
                token=st.session_state.token,
                limit=batch_size,
                skip=start_idx
            )
            
            # Safely handle the DataFrame concatenation
            if batch_df is not None and not batch_df.empty:
                if st.session_state.processed_df is None or st.session_state.processed_df.empty:
                    st.session_state.processed_df = batch_df
                else:
                    st.session_state.processed_df = pd.concat(
                        [st.session_state.processed_df, batch_df], 
                        ignore_index=True
                    )
            
            st.session_state.progress = (batch_num + 1) / num_batches
            st.session_state.current_batch = batch_num + 1
            
            if batch_num % 5 == 0:
                save_progress_to_file()
            
            time.sleep(1)  # Prevent overwhelming the system
            
   except Exception as e:
        st.session_state.error_users.append({
            'batch': batch_num,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        })
   finally:
        st.session_state.job_running = False
        save_progress_to_file()



def start_processing():
    """Start the processing job"""
    if not st.session_state.job_running:
        st.session_state.job_running = True
        total_users = 13000  # Your total user count
        batch_size = 500  # Your preferred batch size
        
        def background_process():
            try:
                # Check if session state variables exist
                 if 'processed_users' not in st.session_state:
                        st.session_state.processed_users = []
                 if 'error_users' not in st.session_state:
                        st.session_state.error_users = []
                    
                 num_batches = (total_users + batch_size - 1) // batch_size
                 for batch_num in range(num_batches):
                    if not st.session_state.job_running:
                        break
                        
                    start_idx = batch_num * batch_size
                    batch_df = get_mfa_status(st.session_state.token, batch_size, start_idx)
                    
                    if batch_df is not None and not batch_df.empty:
                        if 'processed_df' not in st.session_state:
                            st.session_state.processed_df = batch_df
                        else:
                            st.session_state.processed_df = pd.concat(
                                [st.session_state.processed_df, batch_df], 
                                ignore_index=True
                            )
                        
                        st.session_state.progress = (batch_num + 1) / num_batches
                        st.session_state.current_batch = batch_num + 1
                        
                        if batch_num % 5 == 0:
                            save_progress_to_file()
                    
                    time.sleep(1)
            except Exception as e:
                st.error(f"Error in background processing: {str(e)}")
            finally:
                st.session_state.job_running = False
                save_progress_to_file()
        
        thread = Thread(target=background_process)
        thread.daemon = True
        thread.start()

def stop_processing():
    """Stop the processing job"""
    st.session_state.job_running = False
    save_progress_to_file()

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
            if st.button("❌ Cancel", key="cancel_processing", use_container_width=True):
                st.session_state.processed_count = 0
                st.session_state.mfa_data = []
                st.session_state.error_users = []
                st.session_state.processing = False
                st.session_state.processing_status = False
                st.session_state.job_running = False
                if 'processed_df' in st.session_state:
                    del st.session_state.processed_df
                st.experimental_rerun()

        # Show processing status if active
        if st.session_state.processing:
            st.info("Processing in progress... Use the Cancel button to stop.")
    def process_users(self, num_users: int):
        """Process a specific number of users"""
        try:
            st.session_state.processing = True
            batch_df = get_mfa_status(st.session_state.token, num_users, 0)
            
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
        # Initialize processing state
        st.session_state.processing_status = True
        st.session_state.processing = True
        st.session_state.job_running = True
        
        # Initialize processed_df if it doesn't exist or is None
        if 'processed_df' not in st.session_state or st.session_state.processed_df is None:
            st.session_state.processed_df = pd.DataFrame()
        
        # Initialize other necessary session state variables
        if 'progress' not in st.session_state:
            st.session_state.progress = 0
        if 'current_batch' not in st.session_state:
            st.session_state.current_batch = 0
        if 'error_users' not in st.session_state:
            st.session_state.error_users = []

        progress_text = "Processing users in batches..."
        my_bar = st.progress(0)
        status_text = st.empty()
        
        # Start background processing
        thread = Thread(target=self.background_processing, args=(total_users, batch_size))
        thread.daemon = True  # Make thread daemon so it stops when main thread stops
        thread.start()
        
        # Update UI while processing
        while st.session_state.job_running:
            # Update progress bar
            my_bar.progress(st.session_state.progress)
            
            # Update status text
            current_batch = st.session_state.current_batch
            status_text.text(f"Processing batch {current_batch}...")
            
            # Show interim results
            if 'processed_df' in st.session_state and not st.session_state.processed_df.empty:
                df = st.session_state.processed_df.copy()
                st.session_state.df = df
                st.session_state.data_loaded = True
                
                # Display interim analysis
                if current_batch % 2 == 0:
                    st.markdown("## Interim Analysis Results")
                    self.display_metrics_and_charts(df)
                    
                    st.markdown("## Interim Data")
                    st.dataframe(df)
            
            time.sleep(1)
        
        # Final update
        status_text.text("Processing complete!")
        my_bar.progress(1.0)
        
        # Display final results
        if 'processed_df' in st.session_state and not st.session_state.processed_df.empty:
            st.success(f"Successfully processed {len(st.session_state.processed_df)} users!")
            
            # Add download option
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
        st.session_state.job_running = False
        
        # Clear interim data
        if 'processed_df' in st.session_state:
            del st.session_state.processed_df

def background_processing(self, total_users: int, batch_size: int):
    try:
        num_batches = (total_users + batch_size - 1) // batch_size
        
        for batch_num in range(num_batches):
            if not st.session_state.job_running:
                break
                
            start_idx = batch_num * batch_size
            batch_df = self.get_mfa_status_cached(
                token=st.session_state.token,
                limit=batch_size,
                skip=start_idx
            )
            
            # Safely handle the DataFrame concatenation
            if batch_df is not None and not batch_df.empty:
                if st.session_state.processed_df.empty:
                    st.session_state.processed_df = batch_df
                else:
                    st.session_state.processed_df = pd.concat(
                        [st.session_state.processed_df, batch_df], 
                        ignore_index=True
                    )
            
            st.session_state.progress = (batch_num + 1) / num_batches
            st.session_state.current_batch = batch_num + 1
            
            if batch_num % 5 == 0:
                self.save_progress_to_file()
            
            time.sleep(1)  # Prevent overwhelming the system
            
    except Exception as e:
        st.session_state.error_users.append({
            'batch': st.session_state.current_batch,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        })
    finally:
        st.session_state.job_running = False
        self.save_progress_to_file()

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
        try:
            if df is None or df.empty:
                return df

            # Get available columns
            available_columns = df.columns.tolist()
            st.write("Available columns for filtering:", available_columns)

            # Create filters based on available columns
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

            # Apply filters
            filtered_df = df.copy()
            for column, value in filters.items():
                if value:
                    filtered_df = filtered_df[filtered_df[column].str.contains(value, case=False, na=False)]

            return filtered_df

        except Exception as e:
            st.error(f"Error applying filters: {str(e)}")
            return df

    def display_metrics_and_charts(self, df):
       try:
         if df is None or df.empty:
            st.warning("No data available to display metrics and charts")
            return

        # Display raw data for debugging
         st.write("Available columns:", df.columns.tolist())

        # Calculate metrics based on available data
         total_users = len(df)
        
        # Create metrics
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

        # Display detailed DataFrame
         st.dataframe(df)

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
        init_session_state()
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
                
