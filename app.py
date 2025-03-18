import streamlit as st
import numpy as np
from huggingface_hub import hf_hub_download
import time
import os
import re
import joblib
from urllib.parse import urlparse
import datetime

# Page configuration
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered"
)

# Initialize session state for URL history (removing dark mode since Streamlit has built-in dark mode)
if "url_history" not in st.session_state:
    st.session_state.url_history = []

# URL to be analyzed from session state (if available)
url_to_analyze = None
if "url_to_check" in st.session_state:
    url_to_analyze = st.session_state.url_to_check
    del st.session_state.url_to_check

# Custom CSS (simplified without dark mode toggle)
st.markdown("""
<style>
    /* Global Styles */
    .main .block-container {
        padding-top: 2rem;
    }
    
    /* Header styles */
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    
    .sub-header {
        font-size: 1.1rem;
        opacity: 0.8;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    /* Result container */
    .result-container {
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1.5rem 0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    .safe-result {
        background-color: #D1FAE5;
        border: 1px solid #10B981;
    }
    
    .warning-result {
        background-color: #FEF3C7;
        border: 1px solid #F59E0B;
    }
    
    .phishing-result {
        background-color: #FEE2E2;
        border: 1px solid #EF4444;
    }
    
    /* URL display */
    .url-display {
        font-family: monospace;
        padding: 0.8rem;
        background-color: rgba(0,0,0,0.05);
        border-radius: 8px;
        margin-bottom: 1rem;
        word-break: break-all;
    }
    
    /* Risk indicator */
    .risk-header {
        display: flex;
        align-items: center;
        margin-bottom: 1.2rem;
    }
    
    .risk-icon {
        font-size: 2rem;
        margin-right: 0.8rem;
    }
    
    /* Feature list */
    .feature-list {
        background-color: rgba(255,255,255,0.4);
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
    }
    
    .feature-item {
        margin-bottom: 0.5rem;
        padding-left: 1.5rem;
        position: relative;
    }
    
    .feature-item:before {
        content: "•";
        position: absolute;
        left: 0.5rem;
    }
    
    /* Header animation */
    .shield-animation {
        font-size: 5rem;
        text-align: center;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.1); }
        100% { transform: scale(1); }
    }
    
    /* Loading animation */
    .loading-animation {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
    }
    
    .loading-dots {
        display: flex;
        margin-top: 1rem;
    }
    
    .dot {
        width: 12px;
        height: 12px;
        margin: 0 5px;
        border-radius: 50%;
        background-color: #3B82F6;
        animation: bounce 1.5s infinite;
    }
    
    .dot:nth-child(2) {
        animation-delay: 0.2s;
    }
    
    .dot:nth-child(3) {
        animation-delay: 0.4s;
    }
    
    @keyframes bounce {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-10px); }
    }
    
    /* Footer */
    .footer {
        text-align: center;
        font-size: 0.8rem;
        margin-top: 3rem;
        padding-top: 1rem;
        border-top: 1px solid rgba(0,0,0,0.1);
    }
</style>
""", unsafe_allow_html=True)

# App header
st.markdown('<div class="shield-animation">🛡️</div>', unsafe_allow_html=True)
st.markdown('<p class="main-header">Phishing URL Detector</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">🔎 Enter a URL to check if it might be a phishing attempt</p>', unsafe_allow_html=True)

# Sidebar with history
with st.sidebar:
    st.markdown("### 📋 URL History")
    
    if not st.session_state.url_history:
        st.info("No URLs checked yet")
    else:
        for idx, (hist_url, timestamp, risk_level) in enumerate(st.session_state.url_history):
            # Determine icon based on risk level
            if risk_level < 20:
                icon = "🟢"
            elif risk_level < 70:
                icon = "🟠"
            else:
                icon = "🔴"
                
            # Format time as readable
            time_str = timestamp.strftime("%H:%M:%S")
            
            # Create clickable history item
            if st.button(
                f"{icon} {hist_url[:30]}{'...' if len(hist_url) > 30 else ''}",
                key=f"hist_{idx}",
                help=f"Risk: {risk_level:.1f}% - Checked at {time_str}"
            ):
                url_to_analyze = hist_url
        
        if st.button("🗑️ Clear History", use_container_width=True):
            st.session_state.url_history = []
            st.rerun()

def fallback_phishing_check(url):
    """
    A simple fallback method to check for phishing signs when the model is unavailable.
    This is NOT a replacement for ML but provides some basic checks.
    """
    url = url.lower()
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # If domain is empty (user might have entered just a domain name without http://)
    if not domain and '.' in url:
        domain = url
    
    # List of suspicious terms often found in phishing URLs
    suspicious_terms = [
        'secure', 'account', 'banking', 'login', 'signin', 'verify', 
        'authenticate', 'update', 'confirm', 'paypal', 'password',
        'credential', 'wallet', 'alert', 'limited', 'suspended',
        'scam', 'hack', 'free', 'prize', 'winner', 'access', 'verify'
    ]
    
    # List of popular brands often impersonated in phishing
    impersonated_brands = [
        'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 
        'instagram', 'netflix', 'bank', 'chase', 'wells', 'citi', 
        'amex', 'mastercard', 'visa', 'twitter', 'linkedin', 'dropbox'
    ]
    
    # Suspicious TLDs
    suspicious_tlds = [
        'xyz', 'top', 'club', 'online', 'site', 'info', 'biz', 'gq', 
        'ml', 'cf', 'tk', 'ga', 'stream', 'loan', 'date'
    ]
    
    # Check for IP address as domain
    ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
    has_ip_domain = bool(ip_pattern.match(domain))
    
    # Check for suspicious terms in URL
    term_count = sum(1 for term in suspicious_terms if term in url)
    found_terms = [term for term in suspicious_terms if term in url]
    
    # Check if domain contains a brand name but isn't the official domain
    brand_impersonation = False
    impersonated_brand = None
    for brand in impersonated_brands:
        # Check if brand name is in the domain but it's not the main domain
        if brand in domain and not domain.endswith(f".{brand}.com") and not domain == f"{brand}.com":
            brand_impersonation = True
            impersonated_brand = brand
            break
    
    # Check for suspicious TLD
    domain_parts = domain.split('.')
    has_suspicious_tld = False
    if len(domain_parts) > 1 and domain_parts[-1].lower() in suspicious_tlds:
        has_suspicious_tld = True
    
    # Check for excessive subdomains
    subdomain_count = len(domain.split('.')) - 2
    if subdomain_count < 0:
        subdomain_count = 0
    
    # Check for URL length (phishing URLs tend to be longer)
    url_length = len(url)
    
    # Check for presence of @ symbol in URL (often used in phishing)
    has_at_symbol = '@' in url
    
    # Check for unusual port
    has_unusual_port = False
    if ":" in domain and not domain.endswith(":80") and not domain.endswith(":443"):
        has_unusual_port = True
    
    # Check for URL shortener services
    shortener_services = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'is.gd', 'cli.gs', 'ow.ly']
    is_shortened = any(service in domain for service in shortener_services)
    
    # Calculate simple risk score (higher is more risky)
    risk_score = 0
    
    risk_score += term_count * 5  # Each suspicious term adds 5 points
    risk_score += 20 if has_ip_domain else 0  # IP as domain adds 20 points
    risk_score += subdomain_count * 5  # Each subdomain level adds 5 points
    risk_score += 15 if has_at_symbol else 0  # @ symbol adds 15 points
    risk_score += 15 if is_shortened else 0  # URL shortener adds 15 points
    risk_score += min(url_length // 20, 10)  # URL length (max 10 points)
    risk_score += 30 if brand_impersonation else 0  # Brand impersonation is very suspicious
    risk_score += 15 if has_suspicious_tld else 0  # Suspicious TLD
    risk_score += 10 if has_unusual_port else 0  # Unusual port
    risk_score += 25 if 'scam' in domain else 0  # Domain explicitly contains "scam"
    
    # Non-standard TLD (not .com, .org, .net, .edu, .gov)
    std_tlds = ['com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'info', 'biz', 'mil']
    if domain_parts and len(domain_parts) > 1:
        if domain_parts[-1].lower() not in std_tlds:
            risk_score += 5
    
    # Normalize to a percentage (0-100)
    risk_percentage = min(risk_score, 100)
    
    # Collect suspicious features for display
    suspicious_features = []
    if has_ip_domain:
        suspicious_features.append("🔢 Uses IP address instead of domain name")
    if brand_impersonation and impersonated_brand:
        suspicious_features.append(f"🎭 Potential impersonation of {impersonated_brand.capitalize()}")
    if has_suspicious_tld:
        suspicious_features.append(f"🔍 Suspicious top-level domain (.{domain_parts[-1]})")
    if has_at_symbol:
        suspicious_features.append("📧 Contains @ symbol in URL (often used to obscure true destination)")
    if is_shortened:
        suspicious_features.append("🔗 Uses URL shortener service (hides true destination)")
    if found_terms:
        if len(found_terms) > 2:
            suspicious_features.append(f"⚠️ Contains suspicious terms: {', '.join(found_terms[:2])} and others")
        else:
            suspicious_features.append(f"⚠️ Contains suspicious terms: {', '.join(found_terms)}")
    if 'scam' in domain:
        suspicious_features.append("🚨 Domain contains the word 'scam'")
    if subdomain_count > 2:
        suspicious_features.append(f"🔀 Excessive subdomains ({subdomain_count})")
    if has_unusual_port:
        suspicious_features.append("🚪 Uses unusual network port")
    
    return risk_percentage, suspicious_features

@st.cache_resource
def load_model():
    """Load the ML model from HuggingFace Hub (cached for performance)"""
    try:
        # Check if sklearn is available
        import sklearn
        
        REPO_ID = "pirocheto/phishing-url-detection"
        FILENAME = "model.pkl"
        
        try:
            model_path = hf_hub_download(repo_id=REPO_ID, filename=FILENAME)
            # Load the model using joblib
            model = joblib.load(model_path)
            return model, None, False
        except Exception as e:
            error_msg = str(e)
            return None, f"Error loading model: {error_msg}", False
    except ImportError:
        return None, "Error loading model: Missing scikit-learn package. Please install it with 'pip install scikit-learn'.", False

# Load the model
model, error_message, is_locale_error = load_model()

# Show notice when using fallback mode
if model is None:
    st.warning("⚠️ Running in fallback mode: ML model could not be loaded")
    st.info(f"{error_message}\n\nThe app will use a simplified rule-based analysis instead, which is less accurate but still helpful.")

# URL input area
url_col1, url_col2 = st.columns([3, 1])
with url_col1:
    input_url = st.text_input("🔍 Enter URL to check:", 
                             value=url_to_analyze if url_to_analyze else "", 
                             placeholder="https://example.com", 
                             label_visibility="collapsed")

with url_col2:
    analyze_button = st.button("🚀 Analyze", use_container_width=True, type="primary")

# Analyze URL function
def analyze_url(url_to_check):
    # Add http:// prefix if missing
    if not url_to_check.startswith(('http://', 'https://')):
        url_to_check = 'http://' + url_to_check
    
    # Create a container for the loading animation
    loading_container = st.empty()
    
    with loading_container.container():
        # Show custom CSS loading animation
        st.markdown("""
        <div class="loading-animation">
            <div style="font-size: 3rem; margin-bottom: 1rem;">🔍</div>
            <div>Analyzing URL security... please wait</div>
            <div class="loading-dots">
                <div class="dot"></div>
                <div class="dot"></div>
                <div class="dot"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
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
    
    # Add to history (avoid duplicates)
    current_timestamp = datetime.datetime.now()
    history_entry = (url_to_check, current_timestamp, phishing_probability)
    
    # Keep only unique URLs in history (up to 10)
    existing_urls = [entry[0] for entry in st.session_state.url_history]
    if url_to_check not in existing_urls:
        st.session_state.url_history.insert(0, history_entry)
        # Keep only the 10 most recent
        if len(st.session_state.url_history) > 10:
            st.session_state.url_history = st.session_state.url_history[:10]
    
    # Determine risk level
    if phishing_probability < 20:
        risk_class = "safe-result"
        risk_text = "Low Risk"
        risk_icon = "✅"
        emoji = "🛡️"
        message = "This URL appears to be legitimate based on our analysis."
    elif phishing_probability < 70:
        risk_class = "warning-result"
        risk_text = "Moderate Risk"
        risk_icon = "⚠️"
        emoji = "🔔"
        message = "This URL shows some suspicious characteristics. Proceed with caution."
    else:
        risk_class = "phishing-result"
        risk_text = "High Risk"
        risk_icon = "❌"
        emoji = "🚨"
        message = "This URL shows strong characteristics of a phishing attempt. Exercise extreme caution!"
    
    # Display results
    result_container = st.container()
    
    with result_container:
        # Create a styled container with the appropriate background
        st.markdown(f'<div class="result-container {risk_class}">', unsafe_allow_html=True)
        
        # URL display
        st.markdown(f'<div class="url-display">{url_to_check}</div>', unsafe_allow_html=True)
        
        # Risk header
        st.markdown(f'<div class="risk-header">' +
                  f'<span class="risk-icon">{emoji} {risk_icon}</span>' +
                  f'<h2>{risk_text}</h2>' +
                  f'</div>', unsafe_allow_html=True)
        
        # Warning about fallback mode
        if using_fallback:
            st.info("⚠️ Using simplified analysis - model unavailable. Results may be less accurate.")
        
        # Progress bar with clean styling
        st.progress(phishing_probability/100)
        st.markdown(f"### Phishing Probability: {phishing_probability:.1f}%")
        
        # Suspicious features (if any)
        if suspicious_features and (phishing_probability >= 20):
            st.markdown("### 🔍 Suspicious features detected:")
            
            st.markdown('<div class="feature-list">', unsafe_allow_html=True)
            for feature in suspicious_features:
                st.markdown(f'<div class="feature-item">{feature}</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Risk message
        st.markdown(f"### {emoji} {message}")
        
        st.markdown('</div>', unsafe_allow_html=True)

# Process URL analysis - either from input or from session_state
if analyze_button and input_url:
    analyze_url(input_url)
elif url_to_analyze:
    analyze_url(url_to_analyze)

# Example URLs section
st.markdown("### 🧪 Try Example URLs")
col1, col2 = st.columns(2)
with col1:
    st.markdown("**🟢 Likely Safe:**")
    examples_safe = [
        "http://www.medicalnewstoday.com/articles/188939.php",
        "https://github.com",
        "https://www.youtube.com"
    ]
    
    # Use direct analyze_url call instead of session state
    for i, ex in enumerate(examples_safe):
        display_url = ex.split('//')[1][:20]
        if st.button(f"🔗 {display_url}...", key=f"safe_{i}", use_container_width=True):
            analyze_url(ex)

with col2:
    st.markdown("**🔴 Likely Phishing:**")
    examples_phishing = [
        "http://clubedemilhagem.com/home.php",
        "http://login-paypal.com.secure-checkout.info", 
        "http://verify-account.net/signin"
    ]
    
    # Use direct analyze_url call instead of session state
    for i, ex in enumerate(examples_phishing):
        display_url = ex.split('//')[1][:20]
        if st.button(f"🔗 {display_url}...", key=f"phish_{i}", use_container_width=True):
            analyze_url(ex)

# Information section
with st.expander("ℹ️ About this tool"):
    st.markdown("""
    ### 🔍 How it works
    
    This tool uses a machine learning model trained to detect phishing URLs based on various features:
    
    - 🔍 Analyzes URL patterns and domain information
    - 🧠 Uses AI to identify suspicious characteristics
    - 📊 Calculates the probability that a URL is a phishing attempt
    - 💡 Highlights specific suspicious features when detected
    
    ### ⚠️ Disclaimer
    
    While this tool can help identify many phishing attempts, it is not 100% accurate. 
    Always exercise caution when visiting unfamiliar websites or clicking on links from unknown sources.
    """)

st.markdown('<div class="footer">Created with ❤️ using Streamlit and Hugging Face models</div>', unsafe_allow_html=True)