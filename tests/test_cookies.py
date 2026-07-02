"""Infrastructure-cookie classifier (audit/cookies.py)."""
from __future__ import annotations

import pytest

from appsecwatch.audit.cookies import is_infra_cookie


@pytest.mark.parametrize("name", [
    "TS01a5e83e", "TS0139ccaf", "TS01ffd24c",          # F5 ASM / Advanced WAF
    "BIGipServer~prod~pool1", "BIGipServerpool",        # F5 LTM persistence
    "f5avraaaaaaaaaaaaaaaa_session_", "f5_cspm",        # F5 AVR / posture
    "F5_ST", "F5_fullWT", "MRHSession", "LastMRH_Session",  # F5 APM
    "AWSALB", "AWSALBCORS", "NSC_tmas",                 # AWS ALB / Citrix
    "__cflb", "__cf_bm", "incap_ses_123", "visid_incap_1",  # CDN / WAF
    "ak_bmsc", "bm_sz", "_abck",                        # Akamai Bot Manager
    "ADRUM", "ADRUM_BTa", "dtCookie", "rxVisitor",      # AppDynamics / Dynatrace
])
def test_infra_cookies_recognized(name):
    assert is_infra_cookie(name) is True


@pytest.mark.parametrize("name", [
    "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId",     # real session cookies
    "XSRF-TOKEN", "csrftoken", "sid", "auth_token",     # app/auth cookies
    "iSubeForms", "DSBrowserID", "",                    # app cookies / empty
    "TS",                                               # bare TS without hex → not F5
    "tracker", "BIGip",                                 # near-miss, not matched
])
def test_app_cookies_not_infra(name):
    assert is_infra_cookie(name) is False


def test_whitespace_tolerated():
    assert is_infra_cookie("  TS01a5e83e ") is True
