"""
Main entry point for Network Traffic Analyzer
"""

import sys
import os
import streamlit as st
from utils import setup_logging

# Setup logging
logger = setup_logging()

def main():
    """Main application entry point"""
    try:
        # Import and run dashboard
        from dashboard import NetworkDashboard

        dashboard = NetworkDashboard()
        dashboard.run()

    except ImportError as e:
        st.error(f"Import error: {str(e)}")
        st.info("Please ensure all dependencies are installed: pip install -r requirements.txt")
    except Exception as e:
        st.error(f"Application error: {str(e)}")
        logger.error(f"Application error: {str(e)}")

if __name__ == "__main__":
    main()

