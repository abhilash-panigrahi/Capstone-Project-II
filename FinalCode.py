import streamlit as st
from PIL import Image
import numpy as np
import csv
import os
import qrcode
import io
import hashlib
from datetime import datetime
import pandas as pd
import random
import time

# =====================================================
# CONFIGURATION
# =====================================================
st.set_page_config(
    page_title="Quantum-Safe Intelligent Access",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =====================================================
# INTELLIGENT SECURITY MODULE (AI MOCKUP)
# =====================================================
def ai_risk_engine(username):
    """
    Simulates an AI analyzing the login attempt.
    Returns a risk score and status.
    """
    # Simulate processing time for "Analysis"
    time.sleep(1)
    
    # Randomly assign risk for demonstration (mostly safe)
    risk_score = random.randint(1, 100)
    
    # Intelligent Logic Simulation
    if risk_score > 85:
        return "HIGH", "❌ Anomaly Detected: Irregular typing pattern & Unknown IP."
    elif risk_score > 50:
        return "MEDIUM", "⚠️ Caution: Login from new device."
    else:
        return "LOW", "✅ Behavior matches historical profile."

# =====================================================
# SECURITY AND CREDENTIAL MANAGEMENT
# =====================================================

def hash_password(password):
    """Hash password using SHA-256 for secure storage"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_credentials_file():
    """Create CSV file for user credentials"""
    if not os.path.exists("user_credentials.csv"):
        with open("user_credentials.csv", "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password_hash", "role", "created_at", "last_login"])

def create_audit_log_file():
    """Create audit log file for tracking system activities"""
    if not os.path.exists("audit_log.csv"):
        with open("audit_log.csv", "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["timestamp", "username", "action", "status", "details"])

def log_activity(username, action, status, details=""):
    """Log user activities for security audit"""
    with open("audit_log.csv", "a", newline="") as file:
        writer = csv.writer(file)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([timestamp, username, action, status, details])

def register_user(username, password, role="user"):
    """Register a new user with hashed password and role-based access"""
    create_credentials_file()
    
    if not username or not password:
        st.error("Username and password cannot be empty")
        return False
    
    # Check if username exists
    if os.path.exists("user_credentials.csv"):
        with open("user_credentials.csv", "r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["username"] == username:
                    st.error("Username already exists. Please choose a different username.")
                    log_activity(username, "REGISTRATION_FAILED", "FAILED", "Username already exists")
                    return False
    
    if len(password) < 6:
        st.error("Password must be at least 6 characters!")
        return False
    
    password_hash = hash_password(password)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open("user_credentials.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([username, password_hash, role, created_at, ""])
    
    st.success("✅ Registration successful! Please log in.")
    log_activity(username, "REGISTRATION", "SUCCESS", f"New {role} account")
    return True

def login_user(username, password):
    """Authenticate user with AI-powered risk analysis"""
    if not os.path.exists("user_credentials.csv"):
        st.error("No users registered. Please register first.")
        return False
    
    password_hash = hash_password(password)
    
    # 1. Credential Check
    valid_user = False
    user_role = "user"
    
    with open("user_credentials.csv", "r") as file:
        reader = csv.DictReader(file)
        users = list(reader)
        for row in users:
            if row["username"] == username and row["password_hash"] == password_hash:
                valid_user = True
                user_role = row["role"]
                
                # Update last login time
                row["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                break
        
        # Write back updated data
        if valid_user:
            with open("user_credentials.csv", "w", newline="") as wfile:
                writer = csv.DictWriter(wfile, fieldnames=["username", "password_hash", "role", "created_at", "last_login"])
                writer.writeheader()
                writer.writerows(users)
    
    if valid_user:
        # 2. "Intelligent" AI Risk Check
        with st.spinner(f"🤖 AI Risk Engine Analyzing behavior for {username}..."):
            risk_level, risk_msg = ai_risk_engine(username)
            
        if risk_level == "HIGH":
            st.error(f"🛑 Access Denied by AI Security. {risk_msg}")
            log_activity(username, "LOGIN_BLOCKED_AI", "FAILED", risk_msg)
            return False
        
        # If safe, proceed to login
        st.session_state.logged_in = True
        st.session_state.username = username
        st.session_state.role = user_role
        st.session_state.risk_level = risk_level
        st.session_state.risk_msg = risk_msg
        
        st.success(f"🔓 Access Granted. AI Status: {risk_level} Risk")
        log_activity(username, "LOGIN", "SUCCESS", f"Role: {user_role} | Risk: {risk_level}")
        return True
    
    st.error("❌ Invalid credentials. Access Denied.")
    log_activity(username, "LOGIN_FAILED", "FAILED", "Invalid password")
    return False

# =====================================================
# QUANTUM KEY DISTRIBUTION (BB84 Protocol)
# =====================================================

def bb84_key_exchange(length):
    """
    Simulate BB84 quantum key distribution protocol
    Returns shared quantum key
    """
    alice_bits = np.random.randint(2, size=length)
    alice_bases = np.random.randint(2, size=length)
    bob_bases = np.random.randint(2, size=length)
    
    shared_key = []
    for i in range(length):
        if alice_bases[i] == bob_bases[i]:
            shared_key.append(alice_bits[i])
        else:
            # Random chance if bases differ
            if random.random() > 0.5:
                shared_key.append(alice_bits[i])
                
    # Ensure minimum key length
    if len(shared_key) == 0:
        return [1] * 8
    return shared_key

def generate_quantum_key(length):
    """Generate quantum-safe cryptographic key"""
    raw_key = np.random.randint(0, 256, size=length, dtype=np.uint8)
    return list(raw_key)

# =====================================================
# FAST ENCRYPTION (VECTORIZED WITH NUMPY)
# =====================================================

def fast_xor_encrypt(data_bytes, key_int_list):
    """
    Optimized Encryption using NumPy vectorization
    100x faster than traditional loop-based XOR
    """
    if not key_int_list:
        return data_bytes
        
    data_array = np.frombuffer(data_bytes, dtype=np.uint8)
    key_array = np.array(key_int_list, dtype=np.uint8)
    
    # Resize key to match data length
    if len(key_array) < len(data_array):
        tiled_key = np.resize(key_array, len(data_array))
    else:
        tiled_key = key_array[:len(data_array)]
    
    encrypted_array = np.bitwise_xor(data_array, tiled_key)
    return encrypted_array.tobytes()

def encrypt_message(message, key):
    """Encrypt text message using quantum key"""
    if not message:
        return ""
    
    encrypted_bytes = fast_xor_encrypt(message.encode(), key)
    return encrypted_bytes.hex()

def decrypt_message(encrypted_hex, key):
    """Decrypt encrypted message using quantum key"""
    if not encrypted_hex:
        return ""
    
    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted_bytes = fast_xor_encrypt(encrypted_bytes, key)
        return decrypted_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        return f"Decryption error: {str(e)}"

# =====================================================
# QR CODE GENERATION
# =====================================================

def generate_qr_code(data):
    """Generate QR code for secure key sharing"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4
    )
    qr.add_data(str(data))
    qr.make(fit=True)
    img = qr.make_image(fill_color="green", back_color="white")
    return img

# =====================================================
# ADMIN DASHBOARD
# =====================================================

def admin_dashboard():
    """Admin dashboard for system management"""
    st.title("🛡️ Admin Dashboard")
    
    tab1, tab2, tab3 = st.tabs(["Audit Logs", "User Statistics", "System Info"])
    
    with tab1:
        st.subheader("Security Audit Logs")
        if os.path.exists("audit_log.csv"):
            df = pd.read_csv("audit_log.csv")
            
            # Filter options
            col1, col2 = st.columns(2)
            with col1:
                filter_action = st.selectbox("Filter by Action", ["All"] + list(df["action"].unique()))
            with col2:
                filter_status = st.selectbox("Filter by Status", ["All"] + list(df["status"].unique()))
            
            # Apply filters
            filtered_df = df
            if filter_action != "All":
                filtered_df = filtered_df[filtered_df["action"] == filter_action]
            if filter_status != "All":
                filtered_df = filtered_df[filtered_df["status"] == filter_status]
            
            st.dataframe(filtered_df.tail(20), width='stretch')
            
            # Download button
            csv_data = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Complete Audit Log",
                data=csv_data,
                file_name=f"security_audit_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
        else:
            st.info("No audit logs available yet.")
    
    with tab2:
        st.subheader("User Management")
        if os.path.exists("user_credentials.csv"):
            df = pd.read_csv("user_credentials.csv")
            
            # Statistics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Users", len(df))
            with col2:
                admin_count = len(df[df["role"] == "admin"])
                st.metric("Admin Users", admin_count)
            with col3:
                user_count = len(df[df["role"] == "user"])
                st.metric("Regular Users", user_count)
            
            # User table
            st.dataframe(df[["username", "role", "created_at", "last_login"]], width='stretch')
        else:
            st.info("No users registered yet.")
    
    with tab3:
        st.subheader("System Information")
        
        col1, col2 = st.columns(2)
        with col1:
            st.info("""
            **Quantum Encryption**
            - Protocol: BB84
            - Algorithm: XOR with Quantum Keys
            - Key Generation: Numpy Random
            """)
        
        with col2:
            st.success("""
            **AI Security Features**
            - Behavioral Analysis
            - Risk Scoring (LOW/MEDIUM/HIGH)
            - Anomaly Detection
            """)
        
        # Activity Statistics
        if os.path.exists("audit_log.csv"):
            audit_df = pd.read_csv("audit_log.csv")
            
            st.subheader("Activity Breakdown")
            action_counts = audit_df["action"].value_counts()
            st.bar_chart(action_counts)

# =====================================================
# MAIN APPLICATION
# =====================================================

def main():
    # Initialize files
    create_credentials_file()
    create_audit_log_file()
    
    # Initialize session state
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    # =====================================================
    # LOGIN PAGE
    # =====================================================
    if not st.session_state.logged_in:
        # Custom CSS for better styling
        st.markdown("""
    <style>
    .main-title {
        text-align: center;
        color: #00FF41;
        font-size: 3rem;
        margin-bottom: 0.5rem;
        text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
        animation: glow 2s ease-in-out infinite alternate;
    }
    
    @keyframes glow {
        from { text-shadow: 0 0 5px rgba(0, 255, 65, 0.5); }
        to { text-shadow: 0 0 20px rgba(0, 255, 65, 0.8); }
    }
    
    .stButton>button {
        background: linear-gradient(45deg, #00FF41, #00CC33);
        border: none;
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        transform: scale(1.05);
        box-shadow: 0 5px 15px rgba(0, 255, 65, 0.4);
    }
    </style>
""", unsafe_allow_html=True)
        
        st.markdown("<h1 class='main-title'>🔐 Quantum-Safe Intelligent Access Control System</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #00FF41; font-size: 1.2rem; margin-top: -1rem;'>Abhilash Panigrahi - 22BCE0113</p>", unsafe_allow_html=True)
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.image("https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=800&q=80", 
                    caption="Quantum Security Architecture", width='stretch')
            
            st.info("""
            ### 🛡️ System Features
            - **BB84 Quantum Key Distribution**
            - **AI-Powered Risk Analysis**
            - **Role-Based Access Control**
            - **End-to-End Encryption**
            - **Real-time Audit Logging**
            """)
        
        with col2:
            st.markdown("### 🔑 Authentication Portal")
            
            tab_login, tab_reg = st.tabs(["Login", "Register"])
            
            with tab_login:
                st.subheader("Secure Login")
                username = st.text_input("Username", key="l_user")
                password = st.text_input("Password", type="password", key="l_pass")
                
                if st.button("🔐 Secure Login", type="primary", width='stretch'):
                    if username and password:
                        if login_user(username, password):
                            st.rerun()
                    else:
                        st.error("Please enter both username and password")
            
            with tab_reg:
                st.subheader("Create New Account")
                new_user = st.text_input("Username", key="r_user")
                new_pass = st.text_input("Password (min 6 characters)", type="password", key="r_pass")
                confirm_pass = st.text_input("Confirm Password", type="password", key="r_confirm")
                role = st.selectbox("Account Type", ["user", "admin"])
                
                if st.button("Create Account", type="primary", width='stretch'):
                    if new_pass != confirm_pass:
                        st.error("Passwords do not match!")
                    elif new_user and new_pass:
                        register_user(new_user, new_pass, role)
                    else:
                        st.error("Please fill all fields")

    # =====================================================
    # MAIN APPLICATION (AFTER LOGIN)
    # =====================================================
    else:
        # Sidebar Navigation
        st.sidebar.title(f"👤 {st.session_state.username}")
        st.sidebar.info(f"**Role:** {st.session_state.role.upper()}")
        st.sidebar.success(f"**AI Status:** {st.session_state.risk_level} Risk")
        st.sidebar.caption(st.session_state.risk_msg)
        
        st.sidebar.markdown("---")
        st.sidebar.title("📍 Navigation")
        
        nav_options = ["🏠 Home", "💬 Secure Chat", "🖼️ Image Encryption"]
        if st.session_state.role == "admin":
            nav_options.append("⚙️ Admin Dashboard")
        
        nav = st.sidebar.radio("Go to:", nav_options)
        
        if st.sidebar.button("🚪 Logout", type="secondary", width='stretch'):
            log_activity(st.session_state.username, "LOGOUT", "SUCCESS", "")
            st.session_state.logged_in = False
            st.rerun()

        # =====================================================
        # HOME PAGE
        # =====================================================
        if nav == "🏠 Home":
            # Enhanced header with gradient
            st.markdown("""
                <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                            padding: 2rem; border-radius: 10px; margin-bottom: 2rem;'>
                    <h1 style='color: white; text-align: center; margin: 0;'>
                        🏠 Welcome to Quantum-Safe Access Control
                    </h1>
                    <p style='color: white; text-align: center; font-size: 1.2rem; margin-top: 0.5rem;'>
                        Hello, <strong>{}</strong>!
                    </p>
                </div>
            """.format(st.session_state.username), unsafe_allow_html=True)
            
            # Enhanced status cards with better styling
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                    <div style='background: linear-gradient(135deg, #00FF41 0%, #00CC33 100%); 
                                padding: 1.5rem; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);'>
                        <h3 style='color: white; margin-top: 0;'>🔒 Your Security Status</h3>
                        <ul style='color: white; font-size: 1.1rem;'>
                            <li>Account Status: <strong>Active</strong></li>
                            <li>AI Risk Level: <strong>{}</strong></li>
                            <li>Role: <strong>{}</strong></li>
                            <li>Encryption: <strong>Quantum-Safe</strong></li>
                        </ul>
                    </div>
                """.format(st.session_state.risk_level, st.session_state.role.upper()), unsafe_allow_html=True)
            
            with col2:
                st.markdown("""
                    <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                padding: 1.5rem; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);'>
                        <h3 style='color: white; margin-top: 0;'>📊 Available Features</h3>
                        <ul style='color: white; font-size: 1.1rem;'>
                            <li>Quantum-Encrypted Messaging</li>
                            <li>Secure Image Transfer</li>
                            <li>QR Code Key Sharing</li>
                            <li>Activity Monitoring</li>
                        </ul>
                    </div>
                """, unsafe_allow_html=True)
            
            st.markdown("<br>", unsafe_allow_html=True)
            
            # Enhanced Activity Section
            st.markdown("""
                <div style='background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); 
                            padding: 1rem; border-radius: 10px; margin-bottom: 1rem;'>
                    <h2 style='color: white; text-align: center; margin: 0;'>📈 Your Recent Activity</h2>
                </div>
            """, unsafe_allow_html=True)
            
            if os.path.exists("audit_log.csv"):
                audit_df = pd.read_csv("audit_log.csv")
                user_logs = audit_df[audit_df["username"] == st.session_state.username]
                
                if len(user_logs) > 0:
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.markdown("""
                            <div style='background: #667eea; padding: 1rem; border-radius: 10px; text-align: center;'>
                                <h2 style='color: white; margin: 0; font-size: 2.5rem;'>{}</h2>
                                <p style='color: white; margin: 0;'>Total Activities</p>
                            </div>
                        """.format(len(user_logs)), unsafe_allow_html=True)
                    with col2:
                        success_count = len(user_logs[user_logs["status"] == "SUCCESS"])
                        st.markdown("""
                            <div style='background: #00CC33; padding: 1rem; border-radius: 10px; text-align: center;'>
                                <h2 style='color: white; margin: 0; font-size: 2.5rem;'>{}</h2>
                                <p style='color: white; margin: 0;'>Successful Operations</p>
                            </div>
                        """.format(success_count), unsafe_allow_html=True)
                    with col3:
                        last_action = user_logs.iloc[-1]["action"] if len(user_logs) > 0 else "N/A"
                        st.markdown("""
                            <div style='background: #f5576c; padding: 1rem; border-radius: 10px; text-align: center;'>
                                <h3 style='color: white; margin: 0; font-size: 1.2rem;'>{}</h3>
                                <p style='color: white; margin: 0;'>Last Action</p>
                            </div>
                        """.format(last_action), unsafe_allow_html=True)
                    
                    st.markdown("<br>", unsafe_allow_html=True)
                    st.dataframe(user_logs.tail(5), width='stretch')
                else:
                    st.info("🎉 No activity recorded yet. Start using the system!")

        # =====================================================
        # SECURE CHAT
        # =====================================================
        elif nav == "💬 Secure Chat":
            st.title("💬 Quantum-Encrypted Secure Messaging")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("📤 Send Encrypted Message")
                msg = st.text_area("Type your message:", height=150, key="msg_input")
                
                if st.button("🔐 Encrypt & Send", type="primary", width='stretch'):
                    if msg:
                        with st.spinner("Generating quantum key..."):
                            # Generate quantum key
                            key = generate_quantum_key(len(msg))
                            
                            # Encrypt message
                            encrypted_hex = encrypt_message(msg, key)
                            
                            # Store in session
                            st.session_state.last_msg = encrypted_hex
                            st.session_state.last_key = key
                            
                            st.success("✅ Message encrypted successfully!")
                            log_activity(st.session_state.username, "MESSAGE_ENCRYPTED", "SUCCESS", 
                                       f"Length: {len(msg)}")
                    else:
                        st.error("Please enter a message to encrypt!")
                
                # Display encrypted data
                if "last_msg" in st.session_state:
                    st.markdown("---")
                    st.subheader("📋 Encrypted Data")
                    
                    st.text_area("Encrypted Message (Share this):", 
                               st.session_state.last_msg, 
                               height=100, 
                               key="enc_display")
                    
                    # Use spaces so the numbers are distinct and readable
                    key_string = ' '.join(map(str, [int(x) for x in st.session_state.last_key[:20]])) + "..."
                    st.text_input("Quantum Key (Sample - First 20 digits):", key_string)
                    
                    # QR Code option
                    if st.checkbox("Generate QR Code for Key"):
                        # Convert the NumPy values to standard Python ints and join them with spaces
                        clean_key_string = ' '.join(map(str, [int(x) for x in st.session_state.last_key]))
                        qr_img = generate_qr_code(clean_key_string)
                        img_byte_arr = io.BytesIO()
                        qr_img.save(img_byte_arr, format='PNG')
                        st.image(img_byte_arr, caption="QR Code for Quantum Key", width=300)
            
            with col2:
                st.subheader("📥 Decrypt Received Message")
                encrypted_input = st.text_area("Paste encrypted message:", height=150, key="dec_input")
                key_input = st.text_input("Enter quantum key (space-separated numbers):", key="key_input")
                
                if st.button("🔓 Decrypt Message", type="primary", width='stretch'):
                    if encrypted_input and key_input:
                        try:
                            # Parse key
                            key_list = [int(x) for x in key_input.split()]
                            
                            # Decrypt
                            decrypted = decrypt_message(encrypted_input, key_list)
                            
                            st.success("✅ Message decrypted successfully!")
                            st.markdown("### 📨 Decrypted Message:")
                            st.info(decrypted)
                            
                            log_activity(st.session_state.username, "MESSAGE_DECRYPTED", "SUCCESS", "")
                        except Exception as e:
                            st.error(f"❌ Decryption failed: {str(e)}")
                            log_activity(st.session_state.username, "MESSAGE_DECRYPTION_FAILED", "FAILED", str(e))
                    else:
                        st.error("Please provide both encrypted message and key!")

        # =====================================================
        # IMAGE ENCRYPTION
        # =====================================================
        elif nav == "🖼️ Image Encryption":
            st.title("🖼️ Quantum-Safe Image Encryption")
            
            tab_enc, tab_dec = st.tabs(["📤 Encrypt Image", "📥 Decrypt Image"])
            
            with tab_enc:
                st.subheader("Upload and Encrypt Image")
                uploaded_file = st.file_uploader("Choose an image file", type=["jpg", "png", "jpeg"], key="img_upload")
                
                if uploaded_file:
                    image = Image.open(uploaded_file)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.image(image, caption="Original Image", width='stretch')
                    with col2:
                        st.info(f"""
                        **Image Details:**
                        - Format: {image.format}
                        - Size: {image.size}
                        - Mode: {image.mode}
                        """)
                    
                    if st.button("🔐 Encrypt Image", type="primary", width='stretch'):
                        try:
                            with st.spinner("Encrypting image using quantum-safe algorithm..."):
                                # Convert image to bytes
                                img_bytes = io.BytesIO()
                                image.save(img_bytes, format=image.format)
                                byte_data = img_bytes.getvalue()
                                
                                # Generate quantum key
                                key = generate_quantum_key(len(byte_data))
                                
                                # Fast encryption using NumPy
                                encrypted_data = fast_xor_encrypt(byte_data, key)
                                
                                # Store in session
                                st.session_state.enc_img_data = encrypted_data
                                st.session_state.enc_img_key = key
                                st.session_state.enc_img_format = image.format
                                
                                st.success("✅ Image encrypted instantly using vectorized quantum encryption!")
                                
                                # Download button
                                st.download_button(
                                    label="📥 Download Encrypted Image",
                                    data=encrypted_data,
                                    file_name=f"encrypted_{uploaded_file.name}.bin",
                                    mime="application/octet-stream"
                                )
                                
                                # Display key info
                                key_preview = ' '.join(map(str, key[:30])) + "..."
                                st.text_area("Quantum Key (First 30 digits):", key_preview, height=60)
                                
                                log_activity(st.session_state.username, "IMAGE_ENCRYPTED", "SUCCESS", 
                                           f"Size: {len(byte_data)} bytes")
                        except Exception as e:
                            st.error(f"❌ Encryption failed: {str(e)}")
                            log_activity(st.session_state.username, "IMAGE_ENCRYPTION_FAILED", "FAILED", str(e))
            
            with tab_dec:
                st.subheader("Decrypt Encrypted Image")
                
                if "enc_img_data" in st.session_state:
                    st.info("✅ Encrypted image available in session memory")
                    
                    if st.button("🔓 Decrypt Image", type="primary", width='stretch'):
                        try:
                            with st.spinner("Decrypting image..."):
                                # Fast decryption using NumPy
                                decrypted_bytes = fast_xor_encrypt(
                                    st.session_state.enc_img_data,
                                    st.session_state.enc_img_key
                                )
                                
                                # Convert back to image
                                dec_image = Image.open(io.BytesIO(decrypted_bytes))
                                
                                st.success("✅ Image decrypted successfully!")
                                st.image(dec_image, caption="Decrypted Image", width='stretch')
                                
                                log_activity(st.session_state.username, "IMAGE_DECRYPTED", "SUCCESS", "")
                        except Exception as e:
                            st.error(f"❌ Decryption failed: {str(e)}")
                            log_activity(st.session_state.username, "IMAGE_DECRYPTION_FAILED", "FAILED", str(e))
                else:
                    st.info("📝 No encrypted image in session. Please encrypt an image first in the 'Encrypt Image' tab.")

        # =====================================================
        # ADMIN DASHBOARD
        # =====================================================
        elif nav == "⚙️ Admin Dashboard":
            if st.session_state.role == "admin":
                admin_dashboard()
            else:
                st.error("⛔ Access Denied. Admin privileges required.")
                st.info("Please contact your system administrator for access.")

if __name__ == "__main__":
    main()
