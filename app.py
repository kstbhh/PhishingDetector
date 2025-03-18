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

# Initialize session state for URL history
if "url_history" not in st.session_state:
    st.session_state.url_history = []

# URL to be analyzed from session state (if available)
url_to_analyze = None
if "url_to_check" in st.session_state:
    url_to_analyze = st.session_state.url_to_check
    del st.session_state.url_to_check

# Enhanced colorful modern UI styling
st.markdown("""
<style>
    /* Global Styles with colorful gradient background */
    .main {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 1.5rem;
        border-radius: 20px;
    }
    
    .main .block-container {
        padding-top: 2rem;
    }
    
    /* Header styles with gradient text */
    .main-header {
        font-size: 2.5rem;
        font-weight: 800;
        text-align: center;
        margin-bottom: 0.5rem;
        background: linear-gradient(90deg, #4776E6, #8E54E9);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .sub-header {
        font-size: 1.1rem;
        text-align: center;
        margin-bottom: 2rem;
        color: #718096;
    }
    
    /* 3D Monkey Animation CSS */
    .monkey3d-container {
        position: relative;
        width: 120px;
        height: 120px;
        margin: 0 auto;
        margin-bottom: 15px;
        perspective: 500px;
    }
    
    .monkey-face {
        position: relative;
        width: 100px;
        height: 100px;
        margin: 0 auto;
        background: linear-gradient(135deg, #A67C52, #8B5A2B);
        border-radius: 50%;
        box-shadow: 0 10px 25px rgba(0,0,0,0.2);
        transform-style: preserve-3d;
        transform: rotateX(15deg);
        transition: transform 0.3s ease;
    }
    
    .monkey-ears {
        position: absolute;
        width: 45px;
        height: 45px;
        background: linear-gradient(135deg, #8B5A2B, #6B4226);
        border-radius: 50%;
        top: -10px;
        z-index: -1;
    }
    
    .ear-left {
        left: -10px;
        transform: rotate(-15deg);
    }
    
    .ear-right {
        right: -10px;
        transform: rotate(15deg);
    }
    
    .monkey-muzzle {
        position: absolute;
        width: 60px;
        height: 40px;
        background: linear-gradient(135deg, #D2B48C, #BC8F6A);
        border-radius: 40px;
        bottom: 15px;
        left: 50%;
        transform: translateX(-50%);
    }
    
    .eyes-container {
        position: absolute;
        width: 80px;
        height: 30px;
        top: 30px;
        left: 10px;
        display: flex;
        justify-content: space-between;
    }
    
    .eye {
        position: relative;
        width: 28px;
        height: 28px;
        background: white;
        border-radius: 50%;
        overflow: hidden;
        box-shadow: inset 0 0 10px rgba(0,0,0,0.2);
    }
    
    .pupil {
        position: absolute;
        width: 14px;
        height: 14px;
        background: #000;
        border-radius: 50%;
        top: 7px;
        left: 7px;
        transition: all 0.1s;
    }
    
    .monkey-mouth {
        position: absolute;
        width: 30px;
        height: 15px;
        background: #6B4226;
        border-radius: 0 0 15px 15px;
        bottom: 22px;
        left: 50%;
        transform: translateX(-50%);
    }
    
    @keyframes monkeyBreathing {
        0%, 100% { transform: rotateX(15deg) scale(1); }
        50% { transform: rotateX(15deg) scale(1.03); }
    }
    
    .monkey-face {
        animation: monkeyBreathing 3s infinite ease-in-out;
    }
    
    /* Result container with gradient backgrounds */
    .result-container {
        padding: 1.5rem;
        border-radius: 16px;
        margin: 1.5rem 0;
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        transition: transform 0.3s ease;
    }
    
    .result-container:hover {
        transform: translateY(-5px);
    }
    
    .safe-result {
        background: linear-gradient(120deg, #d4fc79, #96e6a1);
        border-left: 6px solid #10B981;
    }
    
    .warning-result {
        background: linear-gradient(120deg, #f6d365, #fda085);
        border-left: 6px solid #F59E0B;
    }
    
    .phishing-result {
        background: linear-gradient(120deg, #ff9a9e, #fad0c4);
        border-left: 6px solid #EF4444;
    }
    
    /* URL display */
    .url-display {
        font-family: monospace;
        padding: 1rem;
        background-color: rgba(255,255,255,0.7);
        border-radius: 10px;
        margin-bottom: 1rem;
        word-break: break-all;
        border: 1px solid rgba(0,0,0,0.1);
    }
    
    /* Risk indicator */
    .risk-header {
        display: flex;
        align-items: center;
        margin-bottom: 1.2rem;
    }
    
    .risk-icon {
        font-size: 2.2rem;
        margin-right: 0.8rem;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.1); }
        100% { transform: scale(1); }
    }
    
    /* Feature list */
    .feature-list {
        background-color: rgba(255,255,255,0.7);
        border-radius: 12px;
        padding: 1.2rem;
        margin: 1rem 0;
        border: 1px solid rgba(0,0,0,0.05);
    }
    
    .feature-item {
        margin-bottom: 0.7rem;
        padding-left: 1.8rem;
        position: relative;
        line-height: 1.5;
    }
    
    .feature-item:before {
        content: "•";
        position: absolute;
        left: 0.7rem;
        font-size: 1.2rem;
        color: #4776E6;
    }
    
    /* Button styling */
    .stButton > button {
        border-radius: 12px;
        padding: 0.5rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 7px 14px rgba(0,0,0,0.1);
    }
    
    /* Text input styling */
    .stTextInput > div > div > input {
        border-radius: 12px;
        border: 2px solid #e2e8f0;
        padding: 0.8rem 1rem;
        font-size: 1rem;
        transition: all 0.3s ease;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #4776E6;
        box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.15);
    }
    
    /* Modal for website visit options */
    .modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: rgba(0,0,0,0.7);
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: center;
        animation: fadeIn 0.3s ease;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    
    .modal-container {
        background: white;
        border-radius: 16px;
        max-width: 500px;
        width: 90%;
        padding: 2rem;
        box-shadow: 0 25px 50px rgba(0,0,0,0.15);
        animation: slideUp 0.3s ease;
    }
    
    @keyframes slideUp {
        from { transform: translateY(50px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }
    
    .modal-safe {
        border-top: 8px solid #10B981;
    }
    
    .modal-warning {
        border-top: 8px solid #F59E0B;
    }
    
    .modal-danger {
        border-top: 8px solid #EF4444;
    }
    
    .modal-header {
        text-align: center;
        margin-bottom: 1.5rem;
    }
    
    .modal-title {
        font-size: 1.8rem;
        font-weight: 700;
        margin: 0.5rem 0;
    }
    
    .modal-safe .modal-title {
        color: #10B981;
    }
    
    .modal-warning .modal-title {
        color: #F59E0B;
    }
    
    .modal-danger .modal-title {
        color: #EF4444;
    }
    
    .modal-danger .modal-icon {
        animation: shake 0.5s infinite;
    }
    
    @keyframes shake {
        0% { transform: translateX(0); }
        25% { transform: translateX(-10px); }
        50% { transform: translateX(0); }
        75% { transform: translateX(10px); }
        100% { transform: translateX(0); }
    }
    
    /* Loading animation */
    .loading-animation {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 2rem;
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
        background-color: #4776E6;
        animation: bounce 1.5s infinite;
    }
    
    .dot:nth-child(2) {
        animation-delay: 0.2s;
        background-color: #8E54E9;
    }
    
    .dot:nth-child(3) {
        animation-delay: 0.4s;
        background-color: #A953C6;
    }
    
    @keyframes bounce {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-10px); }
    }
    
    /* Footer */
    .footer {
        text-align: center;
        font-size: 0.9rem;
        color: #718096;
        margin-top: 3rem;
        padding-top: 1.5rem;
        border-top: 1px solid #e2e8f0;
    }
    
    /* Visit website buttons */
    .visit-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        padding: 0.7rem 1.5rem;
        border-radius: 12px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        text-decoration: none;
        margin-top: 1rem;
    }
    
    .visit-safe {
        background: #10B981;
        color: white !important;
        border: none;
    }
    
    .visit-safe:hover {
        background: #059669;
        text-decoration: none;
    }
    
    .visit-warning {
        background: #F59E0B;
        color: white !important;
        border: none;
    }
    
    .visit-warning:hover {
        background: #D97706;
        text-decoration: none;
    }
    
    .visit-danger {
        background: #EF4444;
        color: white !important;
        border: none;
    }
    
    .visit-danger:hover {
        background: #DC2626;
        text-decoration: none;
    }
</style>
""", unsafe_allow_html=True)

# Add 3D monkey animation
st.markdown("""
<div class="monkey3d-container">
    <div class="monkey-face">
        <div class="monkey-ears ear-left"></div>
        <div class="monkey-ears ear-right"></div>
        <div class="eyes-container">
            <div class="eye">
                <div class="pupil" id="pupil-left"></div>
            </div>
            <div class="eye">
                <div class="pupil" id="pupil-right"></div>
            </div>
        </div>
        <div class="monkey-muzzle"></div>
        <div class="monkey-mouth"></div>
    </div>
</div>

<script>
// Function to make monkey eyes follow cursor/input focus
document.addEventListener('DOMContentLoaded', function() {
    const leftPupil = document.getElementById('pupil-left');
    const rightPupil = document.getElementById('pupil-right');
    
    // Initial position
    updateEyes(10, 10);
    
    // Follow cursor
    document.addEventListener('mousemove', function(e) {
        const x = e.clientX;
        const y = e.clientY;
        updateEyes(x, y);
    });
    
    // Focus on text input when typing
    const inputs = document.querySelectorAll('input[type="text"]');
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            const monkeyFace = document.querySelector('.monkey-face');
            if (monkeyFace) monkeyFace.style.transform = 'rotateX(5deg) scale(1.05)';
        });
        
        input.addEventListener('blur', function() {
            const monkeyFace = document.querySelector('.monkey-face');
            if (monkeyFace) monkeyFace.style.transform = 'rotateX(15deg) scale(1)';
        });
        
        input.addEventListener('input', function() {
            // Make pupils dilate slightly when typing
            leftPupil.style.width = '16px';
            leftPupil.style.height = '16px';
            rightPupil.style.width = '16px';
            rightPupil.style.height = '16px';
            leftPupil.style.top = '6px';
            leftPupil.style.left = '6px';
            rightPupil.style.top = '6px';
            rightPupil.style.left = '6px';
            
            // Reset after a short delay
            setTimeout(() => {
                leftPupil.style.width = '14px';
                leftPupil.style.height = '14px';
                rightPupil.style.width = '14px';
                rightPupil.style.height = '14px';
                leftPupil.style.top = '7px';
                leftPupil.style.left = '7px';
                rightPupil.style.top = '7px';
                rightPupil.style.left = '7px';
            }, 100);
        });
    });
    
    // Update eye positions based on cursor
    function updateEyes(x, y) {
        const eyes = document.querySelectorAll('.eye');
        eyes.forEach(eye => {
            const rect = eye.getBoundingClientRect();
            const eyeX = rect.left + rect.width / 2;
            const eyeY = rect.top + rect.height / 2;
            
            // Calculate angle and distance
            const angle = Math.atan2(y - eyeY, x - eyeX);
            const distance = Math.min(4, Math.sqrt(Math.pow(x - eyeX, 2) + Math.pow(y - eyeY, 2)) / 50);
            
            // Apply movement to pupils (limited range)
            const pupil = eye.querySelector('.pupil');
            const offsetX = Math.cos(angle) * distance;
            const offsetY = Math.sin(angle) * distance;
            
            if (pupil) {
                pupil.style.transform = `translate(${offsetX}px, ${offsetY}px)`;
            }
        });
    }
});
</script>
""", unsafe_allow_html=True)

# Modern app header
st.markdown('<p class="main-header">Phishing URL Detective</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">🔎 Protect yourself from online scams with AI-powered detection</p>', unsafe_allow_html=True)

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
    # Check if we need to pre-populate from an example
    if "example_url" in st.session_state:
        initial_url = st.session_state["example_url"]
        del st.session_state["example_url"]
    elif url_to_analyze:
        initial_url = url_to_analyze
    else:
        initial_url = ""
        
    input_url = st.text_input("🔍 Enter URL to check:", 
                             value=initial_url, 
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
    
    # Determine risk level and prepare result container
    if phishing_probability < 20:
        risk_class = "safe-result"
        risk_text = "Low Risk"
        risk_icon = "✅"
        emoji = "🛡️"
        message = "This URL appears to be legitimate based on our analysis."
        button_class = "visit-safe"
        modal_content = f"""
        <div class="modal-overlay" id="safeModal">
            <div class="modal-container modal-safe">
                <div class="modal-header">
                    <div style="font-size: 3rem;">✅</div>
                    <h3 class="modal-title">Safe URL Detected</h3>
                </div>
                <div>
                    <p>This URL appears to be legitimate based on our analysis:</p>
                    <div class="url-display">{url_to_check}</div>
                    <p>You can safely proceed to this website.</p>
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 1rem; margin-top: 1.5rem;">
                    <a href="{url_to_check}" target="_blank" class="visit-button visit-safe">
                        Visit Website
                    </a>
                    <button onclick="document.getElementById('safeModal').style.display='none';" 
                            style="padding: 0.7rem 1.5rem; border-radius: 12px; border: 1px solid #e2e8f0; background: white;">
                        Cancel
                    </button>
                </div>
            </div>
        </div>
        """
    elif phishing_probability < 70:
        risk_class = "warning-result"
        risk_text = "Moderate Risk"
        risk_icon = "⚠️"
        emoji = "🔔"
        message = "This URL shows some suspicious characteristics. Proceed with caution."
        button_class = "visit-warning"
        modal_content = f"""
        <div class="modal-overlay" id="warningModal">
            <div class="modal-container modal-warning">
                <div class="modal-header">
                    <div style="font-size: 3rem; animation: pulse 1s infinite;">⚠️</div>
                    <h3 class="modal-title">Warning: Moderate Risk</h3>
                </div>
                <div>
                    <p>This URL shows some suspicious characteristics:</p>
                    <div class="url-display">{url_to_check}</div>
                    <p><strong>Are you sure you want to proceed?</strong> Use caution if you choose to continue.</p>
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 1rem; margin-top: 1.5rem;">
                    <a href="{url_to_check}" target="_blank" class="visit-button visit-warning">
                        Proceed Anyway
                    </a>
                    <button onclick="document.getElementById('warningModal').style.display='none';" 
                            style="padding: 0.7rem 1.5rem; border-radius: 12px; border: 1px solid #e2e8f0; background: white;">
                        Cancel
                    </button>
                </div>
            </div>
        </div>
        """
    else:
        risk_class = "phishing-result"
        risk_text = "High Risk"
        risk_icon = "❌"
        emoji = "🚨"
        message = "This URL shows strong characteristics of a phishing attempt. Exercise extreme caution!"
        button_class = "visit-danger"
        modal_content = f"""
        <div class="modal-overlay" id="dangerModal">
            <div class="modal-container modal-danger">
                <div class="modal-header">
                    <div style="font-size: 3rem; animation: shake 0.5s infinite;">🚨</div>
                    <h3 class="modal-title">DANGER: High Risk</h3>
                </div>
                <div>
                    <p>This URL shows strong signs of being a phishing attempt:</p>
                    <div class="url-display">{url_to_check}</div>
                    <p><strong>WARNING:</strong> Visiting this site could put your personal information at risk!</p>
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 1rem; margin-top: 1.5rem;">
                    <a href="{url_to_check}" target="_blank" class="visit-button visit-danger">
                        I Understand the Risk
                    </a>
                    <button onclick="document.getElementById('dangerModal').style.display='none';" 
                            style="padding: 0.7rem 1.5rem; border-radius: 12px; border: 1px solid #e2e8f0; background: white;">
                        Stay Safe
                    </button>
                </div>
            </div>
        </div>
        """
    
    # Display results with enhanced styling
    result_container = st.container()
    
    with result_container:
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
        
        # Visit website button (shows modal when clicked)
        modal_id = "safeModal" if phishing_probability < 20 else "warningModal" if phishing_probability < 70 else "dangerModal"
        st.markdown(f"""
        <button onclick="document.getElementById('{modal_id}').style.display='flex';" class="visit-button {button_class}">
            {risk_icon} Visit Website
        </button>
        {modal_content}
        """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)

# Process URL analysis - either from input or from session_state
if analyze_button and input_url:
    analyze_url(input_url)
elif url_to_analyze:
    analyze_url(url_to_analyze)

# Example URLs section in expander
with st.expander("🧪 Try Example URLs"):
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**🟢 Likely Safe:**")
        examples_safe = [
            "http://www.medicalnewstoday.com/articles/188939.php",
            "https://github.com",
            "https://www.youtube.com"
        ]
        
        # Set example URL to input field when clicked
        for i, ex in enumerate(examples_safe):
            display_url = ex.split('//')[1][:20]
            if st.button(f"🔗 {display_url}...", key=f"safe_{i}", use_container_width=True):
                st.session_state["example_url"] = ex
                st.rerun()

    with col2:
        st.markdown("**🔴 Likely Phishing:**")
        examples_phishing = [
            "http://clubedemilhagem.com/home.php",
            "http://login-paypal.com.secure-checkout.info", 
            "http://verify-account.net/signin"
        ]
        
        # Set example URL to input field when clicked
        for i, ex in enumerate(examples_phishing):
            display_url = ex.split('//')[1][:20]
            if st.button(f"🔗 {display_url}...", key=f"phish_{i}", use_container_width=True):
                st.session_state["example_url"] = ex
                st.rerun()

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

st.markdown('<div class="footer">Created with ❤️ by Kaustubh Somani using Streamlit</div>', unsafe_allow_html=True)