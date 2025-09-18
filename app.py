import streamlit as st
from supabase import create_client, Client
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

# -------------------------
# Supabase Setup
# -------------------------
def init_connection() -> Client:
    url = st.secrets["supabase"]["url"]
    key = st.secrets["supabase"]["key"]
    return create_client(url, key)

supabase = init_connection()

# -------------------------
# Session State
# -------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "role" not in st.session_state:
    st.session_state.role = None
if "user" not in st.session_state:
    st.session_state.user = None
if "page" not in st.session_state:
    st.session_state.page = "dashboard"

# -------------------------
# Signup Function (No Strong Password)
# -------------------------
def signup(email, password, role="user"):
    if len(password) < 6:
        return False, "⚠️ Password must be at least 6 characters long."
    try:
        res = supabase.auth.sign_up({"email": email, "password": password})
        if res.user:
            # Only insert basic required fields that exist in your schema
            supabase.table("user_profiles").insert({
                "id": res.user.id,
                "email": email,
                "role": role
            }).execute()
            return True, "✅ Account created! Please log in."
        return False, str(res)
    except Exception as e:
        return False, str(e)

# -------------------------
# Login Function
# -------------------------
def login(email, password):
    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        if res.user:
            profile = supabase.table("user_profiles").select("*").eq("id", res.user.id).execute()
            if profile.data:
                role = profile.data[0]["role"]
            else:
                role = "user"
            
            st.session_state.authenticated = True
            st.session_state.user = res.user
            st.session_state.role = role
            return True, f"✅ Logged in as {role.capitalize()}"
        return False, "Invalid credentials"
    except Exception as e:
        return False, str(e)

# -------------------------
# Password Reset
# -------------------------
def reset_password(email):
    try:
        supabase.auth.reset_password_for_email(email)
        return True, f"✅ Password reset email sent to {email}."
    except Exception as e:
        return False, str(e)

# -------------------------
# Logout Function
# -------------------------
def logout():
    st.session_state.authenticated = False
    st.session_state.role = None
    st.session_state.user = None
    st.session_state.page = "dashboard"
    supabase.auth.sign_out()
    st.rerun()

# -------------------------
# Admin Helper Functions
# -------------------------
def get_user_analytics():
    """Get user statistics for admin dashboard"""
    users = supabase.table("user_profiles").select("*").execute()
    if not users.data:
        return None
    
    df = pd.DataFrame(users.data)
    
    # Basic stats
    total_users = len(df)
    admin_users = len(df[df['role'] == 'admin'])
    
    return {
        'total_users': total_users,
        'admin_users': admin_users,
        'df': df
    }

def update_user_role(user_id, new_role):
    """Update user role"""
    try:
        supabase.table("user_profiles").update({"role": new_role}).eq("id", user_id).execute()
        return True, f"✅ User role updated to {new_role}"
    except Exception as e:
        return False, str(e)

def update_user_status(user_id, new_status):
    """Update user status"""
    try:
        supabase.table("user_profiles").update({"status": new_status}).eq("id", user_id).execute()
        return True, f"✅ User status updated to {new_status}"
    except Exception as e:
        return False, str(e)

def delete_user(user_id):
    """Delete user (admin only)"""
    try:
        supabase.table("user_profiles").delete().eq("id", user_id).execute()
        return True, "✅ User deleted successfully"
    except Exception as e:
        return False, str(e)

# -------------------------
# User Profile Functions
# -------------------------
def get_user_profile(user_id):
    """Get current user's profile"""
    try:
        profile = supabase.table("user_profiles").select("*").eq("id", user_id).execute()
        return profile.data[0] if profile.data else None
    except Exception as e:
        st.error(f"Error fetching profile: {e}")
        return None

def update_user_profile(user_id, updates):
    """Update user profile"""
    try:
        supabase.table("user_profiles").update(updates).eq("id", user_id).execute()
        return True, "✅ Profile updated successfully"
    except Exception as e:
        return False, str(e)

# -------------------------
# Admin Dashboard
# -------------------------
def admin_dashboard():
    st.title("👑 Admin Dashboard")
    
    # Sidebar navigation
    with st.sidebar:
        st.subheader("Admin Navigation")
        page = st.radio(
            "Select Page",
            ["Overview", "User Management", "Analytics", "System Settings"],
            key="admin_nav"
        )
    
    if page == "Overview":
        admin_overview()
    elif page == "User Management":
        admin_user_management()
    elif page == "Analytics":
        admin_analytics()
    elif page == "System Settings":
        admin_settings()

def admin_overview():
    """Admin overview page"""
    st.subheader("📊 System Overview")
    
    analytics = get_user_analytics()
    if analytics:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Users", analytics['total_users'])
        with col2:
            st.metric("Admin Users", analytics['admin_users'])
        with col3:
            st.metric("Regular Users", analytics['total_users'] - analytics['admin_users'])
        
        # Show all users
        st.subheader("👥 All Users")
        df = analytics['df']
        # Only show columns that exist in your schema
        display_df = df[['email', 'role']].copy()
        st.dataframe(display_df, use_container_width=True)
    else:
        st.info("No user data available yet.")

def admin_user_management():
    """Admin user management page"""
    st.subheader("👥 User Management")
    
    users = supabase.table("user_profiles").select("*").execute()
    if users.data:
        df = pd.DataFrame(users.data)
        
        # Search and filter
        col1, col2 = st.columns([2, 1])
        with col1:
            search_term = st.text_input("🔍 Search users by email")
        with col2:
            role_filter = st.selectbox("Filter by role", ["All", "user", "admin"])
        
        # Filter data
        filtered_df = df.copy()
        if search_term:
            filtered_df = filtered_df[filtered_df['email'].str.contains(search_term, case=False, na=False)]
        if role_filter != "All":
            filtered_df = filtered_df[filtered_df['role'] == role_filter]
        
        st.write(f"Showing {len(filtered_df)} users")
        
        # User management table
        for idx, user in filtered_df.iterrows():
            with st.expander(f"👤 {user['email']} ({user['role']})"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**Email:** {user['email']}")
                    st.write(f"**User ID:** {user['id'][:8]}...")
                
                with col2:
                    new_role = st.selectbox(
                        "Role", 
                        ["user", "admin"], 
                        index=0 if user['role'] == 'user' else 1,
                        key=f"role_{user['id']}"
                    )
                    if st.button("Update Role", key=f"update_role_{user['id']}"):
                        success, msg = update_user_role(user['id'], new_role)
                        if success:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
                
                with col3:
                    # Delete user button (with confirmation)
                    if st.button("🗑️ Delete User", key=f"delete_{user['id']}", type="secondary"):
                        if st.session_state.get(f"confirm_delete_{user['id']}", False):
                            success, msg = delete_user(user['id'])
                            if success:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)
                        else:
                            st.session_state[f"confirm_delete_{user['id']}"] = True
                            st.warning("Click again to confirm deletion")
    else:
        st.info("No users found.")

def admin_analytics():
    """Admin analytics page"""
    st.subheader("📈 Analytics")
    
    analytics = get_user_analytics()
    if analytics and len(analytics['df']) > 0:
        df = analytics['df'].copy()
        
        # Role distribution
        st.subheader("User Role Distribution")
        role_counts = df['role'].value_counts()
        fig_roles = px.pie(values=role_counts.values, names=role_counts.index, 
                          title='User Roles')
        st.plotly_chart(fig_roles, use_container_width=True)
        
        # Simple user table
        st.subheader("All Users")
        display_df = df[['email', 'role']].copy()
        st.dataframe(display_df, use_container_width=True)
        
    else:
        st.info("Not enough data for analytics")

def admin_settings():
    """Admin system settings"""
    st.subheader("⚙️ System Settings")
    
    st.info("🚧 System settings panel coming soon!")
    st.write("Future features:")
    st.write("• Email notification settings")
    st.write("• Security policies")
    st.write("• Data backup/export")
    st.write("• API key management")
    
    # Logout button
    if st.button("🚪 Logout", type="primary"):
        logout()

# -------------------------
# User Dashboard
# -------------------------
def user_dashboard():
    st.title("🙋 User Dashboard")
    
    # Sidebar navigation
    with st.sidebar:
        st.subheader("Navigation")
        page = st.radio(
            "Select Page",
            ["Profile", "Account Settings", "Activity"],
            key="user_nav"
        )
    
    if page == "Profile":
        user_profile()
    elif page == "Account Settings":
        user_account_settings()
    elif page == "Activity":
        user_activity()

def user_profile():
    """User profile page"""
    st.subheader("👤 My Profile")
    
    profile = get_user_profile(st.session_state.user.id)
    if profile:
        st.write("**Account Information**")
        st.write(f"Email: {profile['email']}")
        st.write(f"Role: {profile['role'].title()}")
        st.write(f"User ID: {profile['id'][:8]}...")
    else:
        st.error("Could not load profile information")

def user_account_settings():
    """User account settings"""
    st.subheader("⚙️ Account Settings")
    
    st.write("**Change Password**")
    with st.form("password_form"):
        current_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        
        if st.form_submit_button("Change Password"):
            if new_password != confirm_password:
                st.error("New passwords don't match")
            elif len(new_password) < 6:
                st.error("Password must be at least 6 characters")
            else:
                st.info("🚧 Password change functionality coming soon!")
    
    st.divider()
    
    # Logout button
    if st.button("🚪 Logout", type="primary"):
        logout()

def user_activity():
    """User activity page"""
    st.subheader("📊 My Activity")
    
    profile = get_user_profile(st.session_state.user.id)
    if profile:
        st.write("**Account Information**")
        st.write(f"Email: {profile['email']}")
        st.write(f"Role: {profile['role'].title()}")
        st.write(f"Account ID: {profile['id'][:8]}...")
        
        st.info("🚧 More detailed activity tracking coming soon!")
    else:
        st.error("Could not load activity information")

# -------------------------
# Redirect Logged-in Users
# -------------------------
def redirect_dashboard():
    if st.session_state.role == "admin":
        admin_dashboard()
    else:
        user_dashboard()

# -------------------------
# Streamlit UI
# -------------------------
def main():
    # Configure page
    st.set_page_config(
        page_title="User Management System",
        page_icon="🔐",
        layout="wide"
    )
    
    if not st.session_state.authenticated:
        st.title("🔐 User Management System")
        st.write("Welcome! Please login or create an account to continue.")

        tab1, tab2, tab3 = st.tabs(["Login", "Sign Up", "Reset Password"])

        # ----- LOGIN -----
        with tab1:
            st.subheader("🔑 Login")
            with st.form("login_form"):
                login_email = st.text_input("Email")
                login_password = st.text_input("Password", type="password")
                submit = st.form_submit_button("Login", type="primary")
                
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

        # ----- SIGNUP -----
        with tab2:
            st.subheader("📝 Create Account")
            with st.form("signup_form"):
                signup_email = st.text_input("Email")
                signup_password = st.text_input("Password", type="password")
                role = st.selectbox("Account Type", ["user", "admin"], 
                                  help="Select 'admin' for administrative privileges")
                
                submit = st.form_submit_button("Create Account", type="primary")
                
                if submit:
                    if signup_email and signup_password:
                        success, msg = signup(signup_email, signup_password, role)
                        if success:
                            st.success(msg)
                        else:
                            st.error(msg)
                    else:
                        st.error("Email and password are required")

        # ----- RESET PASSWORD -----
        with tab3:
            st.subheader("🔄 Reset Password")
            with st.form("reset_form"):
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
