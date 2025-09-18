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
def signup(email, password, role="user", first_name="", last_name=""):
    if len(password) < 6:
        return False, "⚠️ Password must be at least 6 characters long."
    try:
        res = supabase.auth.sign_up({"email": email, "password": password})
        if res.user:
            supabase.table("user_profiles").insert({
                "id": res.user.id,
                "email": email,
                "role": role,
                "first_name": first_name,
                "last_name": last_name,
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "status": "active"
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
                # Update last login
                supabase.table("user_profiles").update({
                    "last_login": datetime.now().isoformat()
                }).eq("id", res.user.id).execute()
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
    active_users = len(df[df['status'] == 'active'])
    admin_users = len(df[df['role'] == 'admin'])
    
    # Recent signups (last 30 days)
    df['created_at'] = pd.to_datetime(df['created_at'])
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_signups = len(df[df['created_at'] > thirty_days_ago])
    
    # Users with recent logins (last 7 days)
    df['last_login'] = pd.to_datetime(df['last_login'], errors='coerce')
    seven_days_ago = datetime.now() - timedelta(days=7)
    recent_logins = len(df[df['last_login'] > seven_days_ago])
    
    return {
        'total_users': total_users,
        'active_users': active_users,
        'admin_users': admin_users,
        'recent_signups': recent_signups,
        'recent_logins': recent_logins,
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
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Total Users", analytics['total_users'])
        with col2:
            st.metric("Active Users", analytics['active_users'])
        with col3:
            st.metric("Admin Users", analytics['admin_users'])
        with col4:
            st.metric("Recent Signups (30d)", analytics['recent_signups'])
        with col5:
            st.metric("Recent Logins (7d)", analytics['recent_logins'])
        
        # Recent user activity
        st.subheader("🕐 Recent User Activity")
        df = analytics['df'].copy()
        df['last_login'] = pd.to_datetime(df['last_login'], errors='coerce')
        recent_activity = df.nlargest(10, 'last_login')[['email', 'role', 'last_login', 'status']]
        st.dataframe(recent_activity, use_container_width=True)
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
            with st.expander(f"👤 {user['email']} ({user['role']}) - {user['status']}"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**Name:** {user.get('first_name', '')} {user.get('last_name', '')}")
                    st.write(f"**Created:** {user['created_at'][:10] if user['created_at'] else 'N/A'}")
                    st.write(f"**Last Login:** {user['last_login'][:10] if user['last_login'] else 'Never'}")
                
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
                    new_status = st.selectbox(
                        "Status", 
                        ["active", "inactive", "suspended"], 
                        index=["active", "inactive", "suspended"].index(user.get('status', 'active')),
                        key=f"status_{user['id']}"
                    )
                    if st.button("Update Status", key=f"update_status_{user['id']}"):
                        success, msg = update_user_status(user['id'], new_status)
                        if success:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
                    
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
        
        # User registration trends
        st.subheader("User Registration Trends")
        df['created_at'] = pd.to_datetime(df['created_at'])
        df['registration_date'] = df['created_at'].dt.date
        registration_counts = df.groupby('registration_date').size().reset_index(name='new_users')
        
        fig_reg = px.line(registration_counts, x='registration_date', y='new_users', 
                         title='Daily User Registrations')
        st.plotly_chart(fig_reg, use_container_width=True)
        
        # Role distribution
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("User Role Distribution")
            role_counts = df['role'].value_counts()
            fig_roles = px.pie(values=role_counts.values, names=role_counts.index, 
                              title='User Roles')
            st.plotly_chart(fig_roles)
        
        with col2:
            st.subheader("User Status Distribution")
            status_counts = df['status'].value_counts()
            fig_status = px.pie(values=status_counts.values, names=status_counts.index, 
                               title='User Status')
            st.plotly_chart(fig_status)
        
        # Login activity (for users who have logged in)
        df['last_login'] = pd.to_datetime(df['last_login'], errors='coerce')
        logged_in_users = df.dropna(subset=['last_login'])
        
        if not logged_in_users.empty:
            st.subheader("Login Activity (Last 30 Days)")
            thirty_days_ago = datetime.now() - timedelta(days=30)
            recent_logins = logged_in_users[logged_in_users['last_login'] > thirty_days_ago]
            
            if not recent_logins.empty:
                recent_logins['login_date'] = recent_logins['last_login'].dt.date
                login_counts = recent_logins.groupby('login_date').size().reset_index(name='logins')
                fig_logins = px.bar(login_counts, x='login_date', y='logins',
                                   title='Daily Login Activity')
                st.plotly_chart(fig_logins, use_container_width=True)
            else:
                st.info("No login activity in the last 30 days")
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
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Account Information**")
            st.write(f"Email: {profile['email']}")
            st.write(f"Role: {profile['role'].title()}")
            st.write(f"Status: {profile.get('status', 'active').title()}")
            st.write(f"Member since: {profile['created_at'][:10] if profile['created_at'] else 'N/A'}")
            st.write(f"Last login: {profile['last_login'][:10] if profile['last_login'] else 'Never'}")
        
        with col2:
            st.write("**Personal Information**")
            with st.form("profile_form"):
                first_name = st.text_input("First Name", value=profile.get('first_name', ''))
                last_name = st.text_input("Last Name", value=profile.get('last_name', ''))
                
                if st.form_submit_button("Update Profile"):
                    updates = {
                        'first_name': first_name,
                        'last_name': last_name
                    }
                    success, msg = update_user_profile(st.session_state.user.id, updates)
                    if success:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

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
        st.write("**Account Activity**")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Days as Member", 
                     (datetime.now() - pd.to_datetime(profile['created_at'])).days if profile['created_at'] else 0)
        with col2:
            last_login = profile['last_login']
            if last_login:
                days_since_login = (datetime.now() - pd.to_datetime(last_login)).days
                st.metric("Days Since Last Login", days_since_login)
            else:
                st.metric("Days Since Last Login", "Never")
        
        st.info("🚧 More detailed activity tracking coming soon!")

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
                col1, col2 = st.columns(2)
                with col1:
                    first_name = st.text_input("First Name")
                    signup_email = st.text_input("Email")
                with col2:
                    last_name = st.text_input("Last Name")
                    signup_password = st.text_input("Password", type="password")
                
                role = st.selectbox("Account Type", ["user", "admin"], 
                                  help="Select 'admin' for administrative privileges")
                
                submit = st.form_submit_button("Create Account", type="primary")
                
                if submit:
                    if signup_email and signup_password:
                        success, msg = signup(signup_email, signup_password, role, first_name, last_name)
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
