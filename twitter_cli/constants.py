"""Shared constants for twitter-cli."""

import re

BEARER_TOKEN = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs"
    "%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)

# Default Chrome version — updated by _best_chrome_target() at runtime
_DEFAULT_CHROME_VERSION = "133"
_chrome_version = _DEFAULT_CHROME_VERSION  # mutable, set by sync_chrome_version()


def sync_chrome_version(impersonate_target):
    # type: (str) -> None
    """Sync USER_AGENT / SEC_CH_UA with the actual impersonate target.

    Called once when _get_cffi_session() picks a target (e.g. "chrome136").
    """
    global _chrome_version
    match = re.search(r"(\d+)", impersonate_target)
    if match:
        _chrome_version = match.group(1)


def get_user_agent():
    # type: () -> str
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/%s.0.0.0 Safari/537.36" % _chrome_version
    )


def get_sec_ch_ua():
    # type: () -> str
    return '"Chromium";v="%s", "Not(A:Brand";v="99", "Google Chrome";v="%s"' % (
        _chrome_version, _chrome_version,
    )


# Static Client Hints
SEC_CH_UA_MOBILE = "?0"
SEC_CH_UA_PLATFORM = '"macOS"'

# Legacy aliases — modules that import these get the default value.
# _build_headers() should use get_user_agent() / get_sec_ch_ua() instead.
USER_AGENT = get_user_agent()
SEC_CH_UA = get_sec_ch_ua()
