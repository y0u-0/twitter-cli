"""Cookie authentication for Twitter/X.

Supports:
1. Environment variables: TWITTER_AUTH_TOKEN + TWITTER_CT0
2. Auto-extract from browser via browser-cookie3
   Extracts ALL Twitter cookies for full browser-like fingerprint.
   Prefers in-process extraction (required on macOS for Keychain access),
   falls back to subprocess if in-process fails (e.g. SQLite lock).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from typing import Dict, Optional

from curl_cffi import requests as _cffi_requests

from .constants import BEARER_TOKEN, USER_AGENT

logger = logging.getLogger(__name__)

# Domains to match for Twitter cookies
_TWITTER_DOMAINS = {"x.com", "twitter.com", ".x.com", ".twitter.com"}


def _is_twitter_domain(domain):
    # type: (str) -> bool
    return domain in _TWITTER_DOMAINS or domain.endswith(".x.com") or domain.endswith(".twitter.com")


def load_from_env() -> Optional[Dict[str, str]]:
    """Load cookies from environment variables."""
    auth_token = os.environ.get("TWITTER_AUTH_TOKEN", "")
    ct0 = os.environ.get("TWITTER_CT0", "")
    if auth_token and ct0:
        return {"auth_token": auth_token, "ct0": ct0}
    return None


def verify_cookies(auth_token, ct0, cookie_string=None):
    # type: (str, str, Optional[str]) -> Dict[str, Any]
    """Verify cookies by calling a Twitter API endpoint.

    Uses curl_cffi for proper TLS fingerprint.
    Tries multiple endpoints. Only raises on clear auth failures (401/403).
    For other errors (404, network), returns empty dict (proceed without verification).
    """
    from .client import _best_chrome_target

    urls = [
        "https://api.x.com/1.1/account/verify_credentials.json",
        "https://x.com/i/api/1.1/account/settings.json",
    ]

    # Use full cookie string if available, otherwise minimal
    cookie_header = cookie_string or "auth_token=%s; ct0=%s" % (auth_token, ct0)

    headers = {
        "Authorization": "Bearer %s" % BEARER_TOKEN,
        "Cookie": cookie_header,
        "X-Csrf-Token": ct0,
        "X-Twitter-Active-User": "yes",
        "X-Twitter-Auth-Type": "OAuth2Session",
        "User-Agent": USER_AGENT,
    }

    proxy = os.environ.get("TWITTER_PROXY", "")
    session = _cffi_requests.Session(
        impersonate=_best_chrome_target(),
        proxies={"https": proxy, "http": proxy} if proxy else None,
    )

    for url in urls:
        try:
            resp = session.get(url, headers=headers, timeout=5)
            if resp.status_code in (401, 403):
                raise RuntimeError(
                    "Cookie expired or invalid (HTTP %d). Please re-login to x.com in your browser." % resp.status_code
                )
            if resp.status_code == 200:
                data = resp.json()
                return {"screen_name": data.get("screen_name", "")}
            logger.debug("Verification endpoint %s returned HTTP %d, trying next...", url, resp.status_code)
            continue
        except RuntimeError:
            raise
        except Exception as e:
            logger.debug("Verification endpoint %s failed: %s", url, e)
            continue

    # All endpoints failed with non-auth errors — proceed without verification
    logger.info("Cookie verification skipped (no working endpoint), will verify on first API call")
    return {}


def _extract_cookies_from_jar(jar):
    # type: (Any) -> Optional[Dict[str, str]]
    """Extract Twitter cookies from a cookie jar."""
    result = {}  # type: Dict[str, str]
    all_cookies = {}  # type: Dict[str, str]
    for cookie in jar:
        domain = cookie.domain or ""
        if _is_twitter_domain(domain):
            if cookie.name == "auth_token":
                result["auth_token"] = cookie.value
            elif cookie.name == "ct0":
                result["ct0"] = cookie.value
            if cookie.name and cookie.value:
                all_cookies[cookie.name] = cookie.value
    if "auth_token" in result and "ct0" in result:
        cookies = {"auth_token": result["auth_token"], "ct0": result["ct0"]}
        if all_cookies:
            cookies["cookie_string"] = "; ".join("%s=%s" % (k, v) for k, v in all_cookies.items())
            logger.info("Extracted %d total cookies for full browser fingerprint", len(all_cookies))
        return cookies
    return None


def _extract_in_process():
    # type: () -> Optional[Dict[str, str]]
    """Extract cookies in the main process (required on macOS for Keychain access).

    On macOS, Chrome encrypts cookies using a key stored in the system Keychain.
    Child processes do NOT inherit the parent's Keychain authorization, so
    browser_cookie3 must run in the main process to decrypt cookies.
    """
    try:
        import browser_cookie3
    except ImportError:
        logger.debug("browser_cookie3 not installed, skipping in-process extraction")
        return None

    browsers = [
        ("chrome", browser_cookie3.chrome),
        ("edge", browser_cookie3.edge),
        ("firefox", browser_cookie3.firefox),
        ("brave", browser_cookie3.brave),
    ]

    for name, fn in browsers:
        try:
            jar = fn()
        except Exception as e:
            logger.debug("%s in-process extraction failed: %s", name, e)
            continue
        cookies = _extract_cookies_from_jar(jar)
        if cookies:
            logger.info("Found cookies in %s (in-process)", name)
            return cookies
    return None


def _extract_via_subprocess():
    # type: () -> Optional[Dict[str, str]]
    """Extract cookies via subprocess (fallback if in-process fails, e.g. SQLite lock)."""
    extract_script = '''
import json, sys
try:
    import browser_cookie3
except ImportError:
    print(json.dumps({"error": "browser-cookie3 not installed"}))
    sys.exit(1)

browsers = [
    ("chrome", browser_cookie3.chrome),
    ("edge", browser_cookie3.edge),
    ("firefox", browser_cookie3.firefox),
    ("brave", browser_cookie3.brave),
]

for name, fn in browsers:
    try:
        jar = fn()
    except Exception:
        continue
    result = {}
    all_cookies = {}
    for cookie in jar:
        domain = cookie.domain or ""
        if domain.endswith(".x.com") or domain.endswith(".twitter.com") or domain in ("x.com", "twitter.com", ".x.com", ".twitter.com"):
            if cookie.name == "auth_token":
                result["auth_token"] = cookie.value
            elif cookie.name == "ct0":
                result["ct0"] = cookie.value
            if cookie.name and cookie.value:
                all_cookies[cookie.name] = cookie.value
    if "auth_token" in result and "ct0" in result:
        result["browser"] = name
        result["all_cookies"] = all_cookies
        print(json.dumps(result))
        sys.exit(0)

print(json.dumps({"error": "No Twitter cookies found in any browser. Make sure you are logged into x.com."}))
sys.exit(1)
'''

    try:
        result = subprocess.run(
            [sys.executable, "-c", extract_script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout.strip()
        if not output:
            stderr = result.stderr.strip()
            if stderr:
                logger.debug("Cookie extraction stderr from current env: %s", stderr[:300])
                # Maybe browser-cookie3 not installed, try with uv.
                result2 = subprocess.run(
                    ["uv", "run", "--with", "browser-cookie3", "python3", "-c", extract_script],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                output = result2.stdout.strip()
                if not output:
                    logger.debug("Cookie extraction stderr from uv fallback: %s", result2.stderr.strip()[:300])
                    return None

        data = json.loads(output)
        if "error" in data:
            return None
        logger.info("Found cookies in %s (subprocess)", data.get("browser", "unknown"))

        # Build full cookie string from all extracted cookies
        cookies = {"auth_token": data["auth_token"], "ct0": data["ct0"]}
        all_cookies = data.get("all_cookies", {})
        if all_cookies:
            cookie_str = "; ".join("%s=%s" % (k, v) for k, v in all_cookies.items())
            cookies["cookie_string"] = cookie_str
            logger.info("Extracted %d total cookies for full browser fingerprint", len(all_cookies))
        return cookies
    except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, FileNotFoundError):
        return None


def extract_from_browser() -> Optional[Dict[str, str]]:
    """Auto-extract ALL Twitter cookies from local browser using browser-cookie3.

    Strategy:
    1. Try in-process first (required on macOS for Keychain access)
    2. Fall back to subprocess (handles SQLite lock when browser is running)
    """
    # 1. In-process (works on macOS, may fail with SQLite lock)
    cookies = _extract_in_process()
    if cookies:
        return cookies

    # 2. Subprocess fallback (handles SQLite lock, but fails on macOS Keychain)
    logger.debug("In-process extraction failed, trying subprocess fallback")
    return _extract_via_subprocess()


def get_cookies() -> Dict[str, str]:
    """Get Twitter cookies. Priority: env vars -> browser extraction (Chrome/Edge/Firefox/Brave).

    Raises RuntimeError if no cookies found.
    """
    cookies = None  # type: Optional[Dict[str, str]]

    # 1. Try environment variables
    cookies = load_from_env()
    if cookies:
        logger.info("Loaded cookies from environment variables")

    # 2. Try browser extraction (auto-detect)
    if not cookies:
        cookies = extract_from_browser()

    if not cookies:
        raise RuntimeError(
            "No Twitter cookies found.\n"
            "Option 1: Set TWITTER_AUTH_TOKEN and TWITTER_CT0 environment variables\n"
            "Option 2: Make sure you are logged into x.com in your browser (Chrome/Edge/Firefox/Brave)"
        )

    # Verify only for explicit auth failures; transient endpoint issues are tolerated.
    verify_cookies(cookies["auth_token"], cookies["ct0"], cookies.get("cookie_string"))
    return cookies


