import json
import os
from typing import Dict, Any

class StateManager:
    def __init__(self, state_file: str = '.streamlit/process_state.json'):
        self.state_file = state_file
        os.makedirs(os.path.dirname(state_file), exist_ok=True)
    
    def save_state(self, state: Dict[str, Any]) -> None:
        """Save current processing state"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            print(f"Error saving state: {e}")

    def load_state(self) -> Dict[str, Any]:
        """Load saved processing state"""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading state: {e}")
        return {}

    def clear_state(self) -> None:
        """Clear saved state"""
        try:
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
        except Exception as e:
            print(f"Error clearing state: {e}")