import streamlit as st

from app_common import apply_theme, backend_status, can_read, can_write, current_user, logout, render_login


st.set_page_config(page_title="ThreatGuard AI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
apply_theme()

user = current_user()
if user is None:
    render_login()
    st.stop()

pages = [st.Page("pages/01_dashboard.py", title="Dashboard", icon="🏠", default=True)]
if can_read(user):
    pages.extend([
        st.Page("pages/02_scanner.py", title="Windows Security Scanner", icon="🔎"),
        st.Page("pages/03_knowledge_base.py", title="Knowledge Base", icon="📚"),
        st.Page("pages/06_intelligence_dashboard.py", title="Intelligence Dashboard", icon="🧠"),
        st.Page("pages/07_endpoint_security.py", title="Endpoint Security", icon="🖥️"),
    ])
if can_write(user):
    pages.append(st.Page("pages/04_chatbot.py", title="AI Chatbot", icon="💬"))
pages.append(st.Page("pages/05_account.py", title="Account", icon="👤"))

with st.sidebar:
    st.markdown("<div style='display:flex;align-items:center;gap:11px;padding:4px 0 16px'><div style='width:38px;height:38px;border-radius:12px;background:#1b3658;border:1px solid #315780;display:grid;place-items:center;font-size:20px'>🛡</div><div><div style='font:800 16px Manrope,sans-serif;color:#f1f6ff'>ThreatGuard</div><div style='font-size:11px;color:#87a0bf;letter-spacing:.08em'>SECURITY CENTER</div></div></div>", unsafe_allow_html=True)
    st.caption(f"{user.get('display_name') or user.get('email')} · {user.get('role', 'unknown').replace('_', ' ').title()}")
    connected, description = backend_status()
    st.markdown(f"<div style='display:flex;align-items:center;gap:8px;padding:8px 10px;margin:6px 0 10px;border-radius:9px;background:#121f31;border:1px solid #293c53;color:#aab8ca;font-size:12px'><span style='width:7px;height:7px;border-radius:50%;background:{'#36c98f' if connected else '#f0aa45'}'></span>{'Services operational' if connected else 'Backend connection issue'}</div>", unsafe_allow_html=True)
    if st.button("Sign out", use_container_width=True):
        logout()

navigation = st.navigation(pages, position="sidebar")
navigation.run()
