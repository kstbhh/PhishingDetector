import streamlit as st
import time
from utils import fallback_phishing_check, add_to_history
from ui import show_loading_animation, show_results

def analyze_url(url_to_check, model=None):
    """Analyze URL for phishing indicators and display results"""
    # Add http:// prefix if missing
    if not url_to_check.startswith(('http://', 'https://')):
        url_to_check = 'http://' + url_to_check
    
    # Create a container for the loading animation
    loading_container = st.empty()
    
    # Show loading animation
    with loading_container.container():
        show_loading_animation(st)
    
    # Use fallback method if model isn't available
    if model is None:
        # Simulate analysis steps for better UX
        time.sleep(0.8)
        phishing_probability, suspicious_features = fallback_phishing_check(url_to_check)
        using_fallback = True
    else:
        using_fallback = False
        suspicious_features = []
        try:
            # Simulated loading with steps for better UX
            time.sleep(0.8)
            
            # Make prediction using joblib model
            prediction = model.predict_proba([url_to_check])
            phishing_probability = prediction[0][1] * 100  # Convert to percentage
            
            # If ML model predicts phishing, also run rule-based to get features
            if phishing_probability > 20:
                _, suspicious_features = fallback_phishing_check(url_to_check)
        except Exception as e:
            st.error(f"Error analyzing URL: {str(e)}")
            phishing_probability, suspicious_features = fallback_phishing_check(url_to_check)
            using_fallback = True
    
    # Clear the loading animation
    loading_container.empty()
    
    # Add to URL history
    add_to_history(url_to_check, phishing_probability)
    
    # Display results
    result_container = st.container()
    
    with result_container:
        show_results(url_to_check, phishing_probability, suspicious_features, using_fallback)
