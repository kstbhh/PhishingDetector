import streamlit as st
import numpy as np
import onnxruntime
from huggingface_hub import hf_hub_download
import time

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
</style>
""", unsafe_allow_html=True)

# App header
st.markdown('<p class="main-header">🛡️ Phishing URL Detector</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Enter a URL to check if it might be a phishing attempt</p>', unsafe_allow_html=True)

@st.cache_resource
def load_model():
    """Load the ONNX model from HuggingFace Hub (cached for performance)"""
    REPO_ID = "pirocheto/phishing-url-detection"
    FILENAME = "model.onnx"
    try:
        model_path = hf_hub_download(repo_id=REPO_ID, filename=FILENAME)
        # Initialize ONNX Runtime session
        session = onnxruntime.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"],
        )
        return session
    except Exception as e:
        st.error(f"Error loading model: {str(e)}")
        return None

# Load the model
model = load_model()

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
            
        # Check if model loaded properly
        if model is None:
            st.error("Model failed to load. Please check if the locale environment is properly configured.")
        else:
            try:
                with st.spinner("Analyzing URL..."):
                    # Simulate a brief loading time for better UX
                    time.sleep(0.8)
                    
                    # Make prediction
                    inputs = np.array([url], dtype="str")
                    results = model.run(None, {"inputs": inputs})[1]
                    phishing_probability = results[0][1] * 100  # Convert to percentage
                    
                    # Determine risk level
                    if phishing_probability < 20:
                        risk_class = "safe-url"
                        risk_text = "Low Risk ✅"
                    elif phishing_probability < 70:
                        risk_class = "warning-url"
                        risk_text = "Moderate Risk ⚠️"
                    else:
                        risk_class = "phishing-url"
                        risk_text = "High Risk ❌"
                    
                    # Display results
                    st.markdown(f'<div class="result-box {risk_class}">', unsafe_allow_html=True)
                    st.markdown(f'<div class="url-text">{url}</div>', unsafe_allow_html=True)
                    st.markdown(f'### {risk_text}')
                    st.progress(phishing_probability/100)
                    st.markdown(f"### Phishing Probability: {phishing_probability:.2f}%")
                    
                    if risk_class == "phishing-url":
                        st.warning("This URL shows strong characteristics of a phishing attempt. Exercise extreme caution!")
                    elif risk_class == "warning-url":
                        st.info("This URL shows some suspicious characteristics. Proceed with caution.")
                    else:
                        st.success("This URL appears to be legitimate based on our analysis.")
                        
                    st.markdown('</div>', unsafe_allow_html=True)
                    
            except Exception as e:
                st.error(f"Error analyzing URL: {str(e)}")

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