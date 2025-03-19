import streamlit as st
import time
import os

# Import from local modules
from utils import load_model
from ui import (
    load_css, show_header, show_sidebar, show_url_input, 
    show_examples, show_about_section, show_footer
)
from analysis import analyze_url

# Page configuration
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered"
)

# Initialize session state for URL history
if "url_history" not in st.session_state:
    st.session_state.url_history = []

# Initialize analyze_flag in session state if not present
if "analyze_flag" not in st.session_state:
    st.session_state.analyze_flag = False

# Apply custom CSS
load_css()

# Show app header
show_header()

# Show sidebar with history
show_sidebar()

# Load the ML model
model, error_message, is_locale_error = load_model()

# Show notice when using fallback mode
if model is None:
    st.warning("⚠️ Running in fallback mode: ML model could not be loaded")
    st.info(f"{error_message}\n\nThe app will use a simplified rule-based analysis instead, which is less accurate but still helpful.")

# URL input and analyze button
input_url, analyze_button = show_url_input()

# Process URL analysis - either from input or from session_state
if analyze_button and input_url:
    analyze_url(input_url, model)
elif st.session_state.get("analyze_flag", False) and input_url:
    # Reset the flag
    st.session_state.analyze_flag = False
    analyze_url(input_url, model)
elif "url_to_check" in st.session_state:
    url_to_analyze = st.session_state.url_to_check
    del st.session_state.url_to_check
    analyze_url(url_to_analyze, model)
elif "example_url" in st.session_state and st.session_state.get("analyze_example", False):
    url_to_analyze = st.session_state.example_url
    st.session_state.analyze_example = False
    analyze_url(url_to_analyze, model)

# Show example URLs
show_examples()

# Show information about the tool
show_about_section()

# Show footer
show_footer()