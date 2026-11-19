"""Shared, token-based frontend helpers for the ThreatGuard Streamlit application."""

from __future__ import annotations

from html import escape
import os
from typing import Any
from urllib.parse import urlsplit

import requests
import streamlit as st


BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
READ_ROLES = {"super_admin", "tenant_admin", "security_analyst", "security_operator", "auditor"}
WRITE_ROLES = {"super_admin", "tenant_admin", "security_analyst", "security_operator"}


def apply_theme() -> None:
    """Apply the shared dark SOC visual system to every authenticated page."""
    st.markdown("""
    <style>
      @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap');
      :root { color-scheme: dark; --tg-bg:#0b1120; --tg-panel:#111b2d; --tg-card:#151f32; --tg-border:#26354b; --tg-muted:#91a1b8; --tg-text:#eef4fc; --tg-accent:#62a7ff; }
      html, body, [data-testid="stAppViewContainer"] { background:var(--tg-bg); }
      [data-testid="stHeader"] { background:rgba(11,17,32,.86); border-bottom:1px solid rgba(38,53,75,.65); }
      [data-testid="stAppViewContainer"] * { font-family:'DM Sans',sans-serif; }
      h1,h2,h3,h4 { font-family:'Manrope','DM Sans',sans-serif !important; letter-spacing:-.025em; color:var(--tg-text); }
      h1 { font-size:2rem !important; font-weight:750 !important; margin-bottom:.25rem !important; }
      h2 { font-size:1.35rem !important; font-weight:700 !important; }
      h3 { font-size:1.05rem !important; font-weight:700 !important; }
      p, label, [data-testid="stCaptionContainer"] { color:#a8b6ca; }
      [data-testid="stMainBlockContainer"] { max-width:1500px; padding-top:2rem; padding-bottom:3rem; }
      [data-testid="stSidebar"] { background:#0f1728; border-right:1px solid #243147; }
      [data-testid="stSidebar"] > div:first-child { padding-top:1.1rem; }
      [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#9dadc3; }
      [data-testid="stSidebarNav"] { padding-top:.75rem; }
      [data-testid="stSidebarNav"] a { border-radius:9px; margin:3px 8px; transition:background .16s ease,color .16s ease; }
      [data-testid="stSidebarNav"] a:hover { background:#1a2940; color:#fff; }
      [data-testid="stSidebarNav"] a[aria-current="page"] { background:#1b3150; color:#8fc4ff; border:1px solid #2b4d73; }
      [data-testid="stMetric"] { background:linear-gradient(145deg,#172338,#131e30); border:1px solid #2a3a51; padding:1rem 1.1rem; border-radius:14px; min-height:112px; box-shadow:0 8px 24px rgba(0,0,0,.12); }
      [data-testid="stMetricLabel"] { color:#9aabc1; font-size:.82rem; }
      [data-testid="stMetricValue"] { color:#f4f8ff; font-family:'Manrope',sans-serif; font-weight:750; }
      [data-testid="stVerticalBlockBorderWrapper"] > div { background:#121d2f; border:1px solid #27374e !important; border-radius:14px !important; }
      [data-testid="stDataFrame"], [data-testid="stTable"] { border:1px solid #27374e; border-radius:12px; overflow:hidden; }
      [data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea, [data-testid="stSelectbox"] [role="combobox"], [data-testid="stMultiSelect"] [role="combobox"] { background:#101a2b; border-color:#30415a; border-radius:9px; }
      [data-testid="stButton"] button, [data-testid="stFormSubmitButton"] button { border-radius:9px; font-weight:600; transition:all .15s ease; }
      [data-testid="stButton"] button:hover { border-color:#5a8cc7; transform:translateY(-1px); }
      [data-testid="stButton"] button[kind="primary"], [data-testid="stFormSubmitButton"] button[kind="primary"] { background:#3479cf; border-color:#3479cf; color:white; }
      [data-testid="stAlert"] { border-radius:11px; }
      hr { border-color:#28384e; }
      .tg-eyebrow { color:#70b8ff; font-size:.72rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
      .tg-subtitle { color:#9eacc0; font-size:.98rem; margin-top:0; }
      .tg-panel { background:linear-gradient(145deg,#162238,#121c2d); border:1px solid #2a3c55; border-radius:16px; padding:1.2rem 1.35rem; }
      .tg-panel-title { color:#eff5ff; font:700 1rem 'Manrope',sans-serif; margin-bottom:.25rem; }
      .tg-panel-copy { color:#9eacc0; font-size:.88rem; line-height:1.55; }
      @media (max-width: 700px) { [data-testid="stMainBlockContainer"] { padding:1.25rem 1rem 2rem; } h1 { font-size:1.65rem !important; } }
    </style>
    """, unsafe_allow_html=True)


def page_header(title: str, description: str, eyebrow: str = "THREATGUARD AI") -> None:
    st.markdown(f'<div class="tg-eyebrow">{eyebrow}</div><h1>{title}</h1><p class="tg-subtitle">{description}</p>', unsafe_allow_html=True)


def safe_http_url(value: Any) -> str | None:
    """Return an absolute HTTP(S) URL suitable for an external link, otherwise None."""
    if (not isinstance(value, str) or len(value) > 2048
            or any(ord(char) < 32 or char.isspace() or char == "\\" for char in value)):
        return None
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
        # Accessing .port also validates malformed port syntax.
        _ = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    return candidate


def source_reference_html(label: str, url: Any) -> str | None:
    """Build a safe, clickable external source link for Streamlit Markdown."""
    safe_url = safe_http_url(url)
    if safe_url is None:
        return None
    return (f'<a href="{escape(safe_url, quote=True)}" target="_blank" '
            f'rel="noopener noreferrer">{escape(label)}</a>')


def can_read(user: dict[str, Any]) -> bool:
    return user.get("role") in READ_ROLES


def can_write(user: dict[str, Any]) -> bool:
    return user.get("role") in WRITE_ROLES


def auth_headers() -> dict[str, str]:
    token = st.session_state.get("access_token", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def api_request(method: str, path: str, **kwargs: Any) -> requests.Response:
    headers = dict(kwargs.pop("headers", {}))
    headers.update(auth_headers())
    return requests.request(method, f"{BACKEND_URL}{path}", headers=headers, timeout=kwargs.pop("timeout", 30), **kwargs)


def response_message(response: requests.Response, fallback: str = "The request could not be completed.") -> str:
    try:
        detail = response.json().get("detail", fallback)
    except (ValueError, AttributeError):
        return fallback
    if isinstance(detail, dict):
        detail = detail.get("message") or detail.get("code") or fallback
    return str(detail)[:500]


def show_api_error(response: requests.Response, fallback: str = "The request could not be completed.") -> None:
    if response.status_code == 401:
        clear_session()
        st.error("Your session has expired. Please sign in again.")
        return
    st.error(f"Request failed ({response.status_code}): {response_message(response, fallback)}")


def clear_session() -> None:
    for key in ("access_token", "current_user", "chat_active_id", "chat_draft", "chat_clear_draft"):
        st.session_state.pop(key, None)


def current_user() -> dict[str, Any] | None:
    if not st.session_state.get("access_token"):
        return None
    try:
        response = api_request("GET", "/auth/me", timeout=10)
    except requests.RequestException:
        return None
    if response.status_code == 401:
        clear_session()
        return None
    if not response.ok:
        return None
    user = response.json()
    st.session_state["current_user"] = user
    return user


def render_login() -> None:
    page_header("ThreatGuard AI", "Sign in to your authenticated security workspace.", "SECURITY OPERATIONS")
    try:
        health = requests.get(f"{BACKEND_URL}/health", timeout=5)
        if health.ok:
            st.success("Backend connection is available.")
        else:
            st.warning("The backend returned an unexpected status. Try again shortly.")
    except requests.RequestException:
        st.error("The backend is unavailable. Verify the application services and try again.")

    with st.form("login_form", clear_on_submit=False):
        email = st.text_input("Email", autocomplete="username")
        password = st.text_input("Password", type="password", autocomplete="current-password")
        org_id = st.text_input("Organization ID (only if your email is used in multiple tenants)")
        tenant_id = st.text_input("Tenant ID (only if your email is used in multiple tenants)")
        submitted = st.form_submit_button("Sign in", type="primary")
    if not submitted:
        return
    if not email.strip() or not password:
        st.warning("Enter both your email address and password.")
        return
    if bool(org_id.strip()) != bool(tenant_id.strip()):
        st.warning("Enter both organization and tenant IDs, or leave both blank.")
        return
    try:
        response = requests.post(
            f"{BACKEND_URL}/auth/login",
            json={"email": email.strip(), "password": password,
                  **({"org_id": org_id.strip(), "tenant_id": tenant_id.strip()} if org_id.strip() and tenant_id.strip() else {})},
            timeout=15,
        )
    except requests.RequestException:
        st.error("The backend is unavailable. Your credentials were not sent again.")
        return
    if not response.ok:
        show_api_error(response, "Unable to sign in with those credentials.")
        return
    payload = response.json()
    token = payload.get("access_token")
    user = payload.get("user")
    if not isinstance(token, str) or not token or not isinstance(user, dict):
        st.error("The backend returned an invalid login response.")
        return
    st.session_state["access_token"] = token
    st.session_state["current_user"] = user
    st.rerun()


def logout() -> None:
    try:
        api_request("POST", "/auth/logout", timeout=10)
    except requests.RequestException:
        # Local session state is still cleared, even if the backend is unavailable.
        pass
    clear_session()
    st.rerun()


def backend_status() -> tuple[bool, str]:
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        if not response.ok:
            return False, "Backend returned an unexpected status."
        payload = response.json()
        mongo = payload.get("mongo", "unknown")
        return mongo == "connected", f"Backend: {payload.get('status', 'unknown')} · MongoDB: {mongo}"
    except requests.RequestException:
        return False, "Backend unavailable."
