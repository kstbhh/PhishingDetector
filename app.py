import streamlit as st
import numpy as np
from huggingface_hub import hf_hub_download
import time
import os
import re
import joblib
from urllib.parse import urlparse

# Page configuration
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #4B5563;
        text-align: center;
        margin-bottom: 2rem;
    }
    .result-box {
        padding: 1.5rem;
        border-radius: 10px;
        margin-top: 1.5rem;
    }
    .safe-url {
        background-color: #D1FAE5;
        border: 1px solid #10B981;
    }
    .phishing-url {
        background-color: #FEE2E2;
        border: 1px solid #EF4444;
    }
    .warning-url {
        background-color: #FEF3C7;
        border: 1px solid #F59E0B;
    }
    .url-text {
        font-family: monospace;
        padding: 0.5rem;
        background-color: rgba(0,0,0,0.05);
        border-radius: 5px;
        margin-bottom: 1rem;
    }
    .footer {
        text-align: center;
        color: #6B7280;
        font-size: 0.8rem;
        margin-top: 3rem;
    }
    .stProgress > div > div > div > div {
        height: 15px;
    }
    .notice-box {
        background-color: #EFF6FF;
        border: 1px solid #3B82F6;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    .result-icon {
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
    }
    .result-header {
        display: flex;
        align-items: center;
        margin-bottom: 1rem;
    }
    .result-header h3 {
        margin: 0 0 0 1rem;
    }
    .feature-list {
        background-color: rgba(255,255,255,0.5);
        padding: 0.8rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .feature-item {
        margin-bottom: 0.3rem;
    }
</style>
""", unsafe_allow_html=True)

# App header
st.markdown('<p class="main-header">🛡️ Phishing URL Detector</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Enter a URL to check if it might be a phishing attempt</p>', unsafe_allow_html=True)

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
        suspicious_features.append("Uses IP address instead of domain name")
    if brand_impersonation and impersonated_brand:
        suspicious_features.append(f"Potential impersonation of {impersonated_brand.capitalize()}")
    if has_suspicious_tld:
        suspicious_features.append(f"Suspicious top-level domain (.{domain_parts[-1]})")
    if has_at_symbol:
        suspicious_features.append("Contains @ symbol in URL (often used to obscure true destination)")
    if is_shortened:
        suspicious_features.append("Uses URL shortener service (hides true destination)")
    if found_terms:
        if len(found_terms) > 2:
            suspicious_features.append(f"Contains suspicious terms: {', '.join(found_terms[:2])} and others")
        else:
            suspicious_features.append(f"Contains suspicious terms: {', '.join(found_terms)}")
    if 'scam' in domain:
        suspicious_features.append("Domain contains the word 'scam'")
    if subdomain_count > 2:
        suspicious_features.append(f"Excessive subdomains ({subdomain_count})")
    if has_unusual_port:
        suspicious_features.append("Uses unusual network port")
    
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
    st.markdown('<div class="notice-box">', unsafe_allow_html=True)
    st.warning("⚠️ Running in fallback mode: ML model could not be loaded")
    st.markdown(f"""
    {error_message}
    
    The app will use a simplified rule-based analysis instead, which is less accurate but still helpful.
    """)
    st.markdown('</div>', unsafe_allow_html=True)

# URL input form
with st.form(key="url_form"):
    # Use the stored URL if available
    initial_url = st.session_state.get("url_to_check", "")
    url = st.text_input("Enter URL to check:", value=initial_url, placeholder="https://example.com")
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        submit_button = st.form_submit_button(label="Analyze URL", use_container_width=True)
    
    # Clear the stored URL after using it
    if "url_to_check" in st.session_state:
        del st.session_state.url_to_check

# Process URL when form is submitted
if submit_button:
    if not url:
        st.warning("Please enter a URL to analyze")
    else:
        # Add http:// prefix if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Use fallback method if model isn't available
        if model is None:
            phishing_probability, suspicious_features = fallback_phishing_check(url)
            using_fallback = True
        else:
            using_fallback = False
            suspicious_features = []
            try:
                with st.spinner("Analyzing URL..."):
                    # Simulate a brief loading time for better UX
                    time.sleep(0.8)
                    
                    # Make prediction using joblib model
                    prediction = model.predict_proba([url])
                    phishing_probability = prediction[0][1] * 100  # Convert to percentage
                    
                    # If ML model predicts phishing, also run rule-based to get features
                    if phishing_probability > 20:
                        _, suspicious_features = fallback_phishing_check(url)
            except Exception as e:
                st.error(f"Error analyzing URL: {str(e)}")
                phishing_probability, suspicious_features = fallback_phishing_check(url)
                using_fallback = True
        
        # Determine risk level
        if phishing_probability < 20:
            risk_class = "safe-url"
            risk_text = "Low Risk"
            risk_icon = "✅"
            message = "This URL appears to be legitimate based on our analysis."
        elif phishing_probability < 70:
            risk_class = "warning-url"
            risk_text = "Moderate Risk"
            risk_icon = "⚠️"
            message = "This URL shows some suspicious characteristics. Proceed with caution."
        else:
            risk_class = "phishing-url"
            risk_text = "High Risk"
            risk_icon = "❌"
            message = "This URL shows strong characteristics of a phishing attempt. Exercise extreme caution!"
        
        # Display results
        st.markdown(f'<div class="result-box {risk_class}">', unsafe_allow_html=True)
        
        # URL display
        st.markdown(f'<div class="url-text">{url}</div>', unsafe_allow_html=True)
        
        # Header with icon
        st.markdown(f'<div class="result-header"><span class="result-icon">{risk_icon}</span><h3>{risk_text}</h3></div>', unsafe_allow_html=True)
        
        # Warning about fallback mode
        if using_fallback:
            st.info("⚠️ Using simplified analysis - model unavailable. Results may be less accurate.")
        
        # Progress bar and percentage
        st.progress(phishing_probability/100)
        st.markdown(f"**Phishing Probability: {phishing_probability:.1f}%**")
        
        # Suspicious features (if any)
        if suspicious_features and (phishing_probability >= 20):
            st.markdown("### Suspicious features detected:")
            st.markdown('<div class="feature-list">', unsafe_allow_html=True)
            for feature in suspicious_features:
                st.markdown(f'<div class="feature-item">• {feature}</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Risk message
        st.markdown(f"### {message}")
            
        st.markdown('</div>', unsafe_allow_html=True)

# Example URLs section
with st.expander("Try example URLs"):
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Likely Safe:**")
        examples_safe = [
            "http://www.medicalnewstoday.com/articles/188939.php",
            "https://github.com",
            "https://www.youtube.com"
        ]
        for ex in examples_safe:
            if st.button(ex, key=f"safe_{ex}"):
                st.session_state.url_to_check = ex
                st.rerun()
    
    with col2:
        st.markdown("**Likely Phishing:**")
        examples_phishing = [
            "https://clubedemilhagem.com/home.php",
            "http://login-paypal.com.secure-checkout.info",
            "http://verify-account.net/signin"
        ]
        for ex in examples_phishing:
            if st.button(ex, key=f"phish_{ex}"):
                st.session_state.url_to_check = ex
                st.rerun()

# Information section
with st.expander("About this tool"):
    st.markdown("""
    This tool uses a machine learning model trained to detect phishing URLs based on various features.
    
    **How it works:**
    - The model analyzes URL patterns, domain information, and other characteristics
    - It then calculates the probability that the URL is a phishing attempt
    - Higher percentages indicate higher likelihood of being a phishing site
    
    **Disclaimer:** While this tool can help identify many phishing attempts, it is not 100% accurate. 
    Always exercise caution when visiting unfamiliar websites or clicking on links from unknown sources.
    """)

st.markdown('<div class="footer">Created with ❤️ using Streamlit and Hugging Face models</div>', unsafe_allow_html=True)