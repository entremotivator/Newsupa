import streamlit as st
from supabase import create_client, Client
import pandas as pd

# -------------------------
# Supabase Setup
# -------------------------
def init_connection() -> Client:
    url = st.secrets["supabase"]["url"]
    key = st.secrets["supabase"]["key"]
    return create_client(url, key)

supabase = init_connection()

# -------------------------
# Session State Initialization
# -------------------------
for key, default in {
    "authenticated": False,
    "role": None,
    "user": None,
    "page": "dashboard",
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# -------------------------
# Signup Function with Metadata & Email Verification
# -------------------------
def signup(email, password, role="user"):
    if len(password) < 6:
        return False, "⚠️ Password must be at least 6 characters long."

    try:
        res = supabase.auth.sign_up(
            {
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "role": role,
                    },
                },
            }
        )
        if res.user:
            return (
                True,
                "✅ Account created! Please verify your email before logging in.",
            )
        else:
            return False, str(res)
    except Exception as e:
        return False, f"Error during signup: {e}"

# -------------------------
# Login Function with Email Verification Check
# -------------------------
def login(email, password):
    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        if res.user:
            if not res.user.email_confirmed_at:
                return False, "⚠️ Please verify your email before logging in."

            profile_resp = supabase.table("user_profiles").select("*").eq("id", res.user.id).execute()
            role = profile_resp.data[0]["role"] if profile_resp.data else "user"

            st.session_state.authenticated = True
            st.session_state.user = res.user
            st.session_state.role = role
            return True, f"✅ Logged in as {role.capitalize()}"
        return False, "Invalid email or password."
    except Exception as e:
        return False, f"Error during login: {e}"

# -------------------------
# Password Reset Function with Feedback
# -------------------------
def reset_password(email):
    try:
        supabase.auth.reset_password_for_email(email)
        return True, f"✅ Password reset email sent to {email}."
    except Exception as e:
        return False, f"Error sending reset email: {e}"

# -------------------------
# Logout Function
# -------------------------
def logout():
    supabase.auth.sign_out()
    st.session_state.authenticated = False
    st.session_state.role = None
    st.session_state.user = None
    st.session_state.page = "dashboard"
    st.experimental_rerun()

# -------------------------
# User Profile Functions
# -------------------------
def get_user_profile(user_id):
    try:
        profile = supabase.table("user_profiles").select("*").eq("id", user_id).execute()
        return profile.data[0] if profile.data else None
    except Exception as e:
        st.error(f"Error fetching profile: {e}")
        return None

# -------------------------
# Redirect User to Dashboard Based on Role
# -------------------------
def redirect_dashboard():
    if st.session_state.role == "admin":
        admin_dashboard()
    else:
        user_dashboard()

# -------------------------
# Admin Dashboard Placeholder
# -------------------------
def admin_dashboard():
    st.title("👑 Admin Dashboard")
    st.write("Welcome, admin! (Admin features to be implemented.)")
    if st.button("Logout"):
        logout()

# -------------------------
# User Dashboard Placeholder
# -------------------------
def user_dashboard():
    st.title("🙋 User Dashboard")
    profile = get_user_profile(st.session_state.user.id)
    if profile:
        st.write(f"Welcome, {profile.get('email')}!")
        st.write(f"Role: {profile.get('role').capitalize()}")
    else:
        st.error("Failed to load user profile.")
    if st.button("Logout"):
        logout()

# -------------------------
# Streamlit UI Main
# -------------------------
def main():
    st.set_page_config(page_title="User Management System", page_icon="🔐", layout="wide")

    if not st.session_state.authenticated:
        st.title("🔐 User Management System")
        st.write("Welcome! Please login or create an account to continue.")
        tab1, tab2, tab3 = st.tabs(["Login", "Sign Up", "Reset Password"])

        with tab1:
            st.subheader("🔑 Login")
            with st.form("login_form"):
                login_email = st.text_input("Email")
                login_password = st.text_input("Password", type="password")
                submit = st.form_submit_button("Login")
                if submit:
                    if login_email and login_password:
                        success, msg = login(login_email, login_password)
                        if success:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
                    else:
                        st.error("Please fill in all fields")

        with tab2:
            st.subheader("📝 Create Account")
            with st.form("signup_form"):
                signup_email = st.text_input("Email")
                signup_password = st.text_input("Password", type="password")
                role_choice = st.selectbox(
                    "Account Type", ["user", "admin"], help="Select 'admin' for admin privileges."
                )
                submit = st.form_submit_button("Create Account")
                if submit:
                    if signup_email and signup_password:
                        success, msg = signup(signup_email, signup_password, role_choice)
                        if success:
                            st.success(msg)
                        else:
                            st.error(msg)
                    else:
                        st.error("Email and password are required")

        with tab3:
            st.subheader("🔄 Reset Password")
            with st.form("reset_password_form"):
                reset_email = st.text_input("Enter your email address")
                submit = st.form_submit_button("Send Reset Email")
                if submit:
                    if reset_email:
                        success, msg = reset_password(reset_email)
                        if success:
                            st.success(msg)
                        else:
                            st.error(msg)
                    else:
                        st.error("Please enter your email address")

    else:
        redirect_dashboard()

if __name__ == "__main__":
    main()
