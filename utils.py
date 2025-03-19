import streamlit as st
from huggingface_hub import hf_hub_download
import joblib
import datetime
import re
from urllib.parse import urlparse

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

def add_to_history(url, risk_percentage):
    """Add URL to history with timestamp and risk level"""
    current_timestamp = datetime.datetime.now()
    history_entry = (url, current_timestamp, risk_percentage)
    
    # Keep only unique URLs in history (up to 10)
    existing_urls = [entry[0] for entry in st.session_state.url_history]
    if url not in existing_urls:
        st.session_state.url_history.insert(0, history_entry)
        # Keep only the 10 most recent
        if len(st.session_state.url_history) > 10:
            st.session_state.url_history = st.session_state.url_history[:10]
