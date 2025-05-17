import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64

# ------------------ Helper functions ------------------

def generate_fernet_key(passkey: str) -> bytes:
    """Derive a Fernet key from the user passkey via SHA‑256."""
    digest = hashlib.sha256(passkey.encode()).digest()  # 32 bytes
    return base64.urlsafe_b64encode(digest)


def encrypt_text(plain_text: str, passkey: str) -> str:
    """Encrypt plain_text using Fernet derived from passkey."""
    key = generate_fernet_key(passkey)
    f = Fernet(key)
    return f.encrypt(plain_text.encode()).decode()


def decrypt_text(cipher_text: str, passkey: str) -> str | None:
    """Attempt to decrypt cipher_text with passkey. Return None on failure."""
    try:
        key = generate_fernet_key(passkey)
        f = Fernet(key)
        return f.decrypt(cipher_text.encode()).decode()
    except Exception:
        return None


def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

# ------------------ In‑memory storage ------------------

if "stored_data" not in st.session_state:
    # {hashed_passkey: encrypted_text}
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True

# ------------------ Page routing ------------------

PAGES = ["Home", "Insert Data", "Retrieve Data", "Login"]

if not st.session_state.authorized:
    page = "Login"
else:
    page = st.sidebar.selectbox("Navigate", PAGES, index=0)

# ------------------ Login Page ------------------

def login_page():
    st.title("🔐 Reauthorization Required")
    pwd = st.text_input("Enter master password", type="password")
    if st.button("Login"):
        # Simple demo: password == "admin"  (In production replace)
        if pwd == "admin":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("Logged in! Navigate using sidebar.")
        else:
            st.error("Wrong password.")

# ------------------ Home Page ------------------

def home_page():
    st.title("🔒 Secure Data Vault")
    st.markdown("Choose an action from the sidebar:")
    st.markdown("- **Insert Data** to store new text\n- **Retrieve Data** to decrypt stored text")

# ------------------ Insert Data Page ------------------

def insert_page():
    st.header("📝 Store New Data")
    text = st.text_area("Text to encrypt")
    passkey = st.text_input("Choose a passkey", type="password")
    if st.button("Encrypt & Save"):
        if not text or not passkey:
            st.warning("Both fields are required.")
            return
        cipher = encrypt_text(text, passkey)
        hpass = hash_passkey(passkey)
        st.session_state.stored_data[hpass] = cipher
        st.success("Data encrypted and stored in memory!")

# ------------------ Retrieve Data Page ------------------

def retrieve_page():
    st.header("🔑 Retrieve Data")
    passkey = st.text_input("Enter passkey to decrypt", type="password")
    if st.button("Decrypt"):
        hpass = hash_passkey(passkey)
        cipher = st.session_state.stored_data.get(hpass)
        if cipher:
            plain = decrypt_text(cipher, passkey)
            if plain is not None:
                st.success("Decryption successful!")
                st.code(plain)
                st.session_state.failed_attempts = 0
            else:
                st.error("Decryption failed. (Corrupted data?)")
        else:
            st.session_state.failed_attempts += 1
            st.error(f"Invalid passkey. Attempts: {st.session_state.failed_attempts}/3")
        if st.session_state.failed_attempts >= 3:
            st.session_state.authorized = False
            st.experimental_rerun()

# ------------------ Render ------------------

if page == "Login":
    login_page()
elif page == "Home":
    home_page()
elif page == "Insert Data":
    insert_page()
elif page == "Retrieve Data":
    retrieve_page()
