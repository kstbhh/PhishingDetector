import streamlit as st

def load_css():
    """Load custom CSS styling for the app"""
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

def show_header():
    """Display app header with animations"""
    st.markdown('<div class="shield-animation">🛡️</div>', unsafe_allow_html=True)
    st.markdown('<p class="main-header">Phishing URL Detector</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">🔎 Enter a URL to check if it might be a phishing attempt</p>', unsafe_allow_html=True)

def show_loading_animation(container):
    """Display loading animation in the provided container"""
    container.markdown("""
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

def show_sidebar():
    """Display sidebar with URL history"""
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
                    st.session_state["url_to_check"] = hist_url
                    st.rerun()
            
            if st.button("🗑️ Clear History", use_container_width=True):
                st.session_state.url_history = []
                st.rerun()

def show_url_input():
    """Display URL input area and return user input and analyze button status"""
    # Use a form to capture Enter key presses
    with st.form(key="url_form", clear_on_submit=False):
        url_col1, url_col2 = st.columns([3, 1])
        
        with url_col1:
            # Check if we need to pre-populate from an example
            if "example_url" in st.session_state:
                initial_url = st.session_state["example_url"]
            elif "url_to_check" in st.session_state:
                initial_url = st.session_state["url_to_check"]
            else:
                initial_url = ""
                
            input_url = st.text_input("🔍 Enter URL to check:", 
                                    value=initial_url, 
                                    placeholder="https://example.com", 
                                    label_visibility="collapsed",
                                    key="url_input")

        with url_col2:
            analyze_button = st.form_submit_button("🚀 Analyze", use_container_width=True, type="primary")
        
        # Set a flag in session state when form is submitted (either by button or enter key)
        if analyze_button:
            st.session_state.analyze_flag = True
            
    return input_url, analyze_button

def show_examples():
    """Display example URLs section"""
    with st.expander("🧪 Try Example URLs"):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**🟢 Likely Safe:**")
            examples_safe = [
                "https://nitte.edu.in/nmit/",
                "http://www.1337x.to",
                "https://github.com",
                "https://www.youtube.com"
            ]
            
            # Set example URL to input field when clicked and trigger analysis
            for i, ex in enumerate(examples_safe):
                display_url = ex.split('//')[1][:20]
                if st.button(f"🔗 {display_url}...", key=f"safe_{i}", use_container_width=True):
                    st.session_state["example_url"] = ex
                    st.session_state["analyze_example"] = True
                    st.rerun()

        with col2:
            st.markdown("**🔴 Likely Phishing:**")
            examples_phishing = [
                "https://amazon.in@linkir.cyou?id=11735124372375",
                "http://clubedemilhagem.com/home.php",
                "http://login-paypal.com.secure-checkout.info", 
                "http://verify-account.net/signin"
            ]
            
            # Set example URL to input field when clicked and trigger analysis
            for i, ex in enumerate(examples_phishing):
                display_url = ex.split('//')[1][:20]
                if st.button(f"🔗 {display_url}...", key=f"phish_{i}", use_container_width=True):
                    st.session_state["example_url"] = ex
                    st.session_state["analyze_example"] = True
                    st.rerun()

def show_about_section():
    """Display information about the tool"""
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

def show_results(url, phishing_probability, suspicious_features, using_fallback=False):
    """Display analysis results for a URL"""
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
    
    # URL display
    st.markdown(f'<div class="url-display">{url}</div>', unsafe_allow_html=True)
    
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

def show_footer():
    """Display footer with attribution"""
    st.markdown('<div class="footer">Made with ❤️ by Kaustubh using Streamlit</div>', unsafe_allow_html=True)
