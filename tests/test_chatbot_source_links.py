from __future__ import annotations

import sys
from pathlib import Path


FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
if str(FRONTEND) not in sys.path:
    sys.path.insert(0, str(FRONTEND))

from app_common import safe_http_url, source_reference_html  # noqa: E402


def test_source_reference_renders_clickable_escaped_http_link():
    link = source_reference_html("Source <1>", "https://intel.example/advisory?id=one&view=full")

    assert link is not None
    assert 'href="https://intel.example/advisory?id=one&amp;view=full"' in link
    assert ">Source &lt;1&gt;</a>" in link
    assert 'target="_blank"' in link
    assert 'rel="noopener noreferrer"' in link


def test_source_reference_rejects_non_http_and_malformed_urls():
    for url in (
        "javascript:alert(1)",
        "data:text/html,unsafe",
        "//intel.example/advisory",
        "https://user:password@intel.example/advisory",
        "https://intel.example:invalid/advisory",
        'https://intel.example/" onclick="alert(1)',
    ):
        assert safe_http_url(url) is None
        assert source_reference_html("Source", url) is None


def test_source_reference_accepts_plain_http_and_https_only():
    assert safe_http_url("http://intel.example/advisory") == "http://intel.example/advisory"
    assert safe_http_url("https://intel.example/advisory") == "https://intel.example/advisory"


def test_source_reference_markup_runs_in_streamlit():
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_string(
        "import streamlit as st\n"
        "from app_common import source_reference_html\n"
        "st.markdown(source_reference_html('Source reference 1', 'https://intel.example/advisory'), unsafe_allow_html=True)\n"
    ).run()

    assert not app.exception
    assert any("Source reference 1" in element.value for element in app.markdown)
