import json
import sys
import time
from urllib.parse import urlencode

import requests

from ldapmap_constants import ERROR_SLEEP_SECONDS, TIMEOUT, TIMEOUT_RETRIES


def build_session(proxy: str | None) -> requests.Session:
    """Create and return a requests.Session optionally configured with a proxy."""
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        # Disable SSL verification when using a proxy (e.g. Burp Suite)
        session.verify = False
    return session


def send_request(
    session: requests.Session,
    url: str,
    data: dict,
    verbose: bool = False,
    use_json: bool = False,
    timeout: float = TIMEOUT,
    timeout_retries: int = TIMEOUT_RETRIES,
    sleep_after_error: bool = True,
    error_sleep_seconds: float = ERROR_SLEEP_SECONDS,
) -> requests.Response | None:
    """
    Send a POST request and return the response.

    When *verbose* is True, each outgoing payload is printed to stdout before
    the request is dispatched.

    When *use_json* is True the payload is sent as a JSON body
    (``Content-Type: application/json``); otherwise it is sent as
    URL-encoded form data.

    Returns None on connection errors so callers can handle failures gracefully.
    """
    if verbose:
        if use_json:
            print(f"[V] POST {url}  json={json.dumps(data)}")
        else:
            print(f"[V] POST {url}  data={urlencode(data)}")
    post_kwargs = {"json": data} if use_json else {"data": data}
    attempts = max(1, timeout_retries + 1)
    for attempt in range(1, attempts + 1):
        try:
            resp = session.post(url, **post_kwargs, timeout=timeout)
            if verbose:
                print(f"[V] HTTP {resp.status_code}")
            return resp
        except requests.exceptions.ConnectionError as exc:
            print(f"[!] Connection error: {exc}", file=sys.stderr)
            if sleep_after_error and error_sleep_seconds > 0:
                time.sleep(error_sleep_seconds)
            return None
        except requests.exceptions.Timeout:
            if attempt < attempts:
                print(
                    f"[!] Request timed out (attempt {attempt}/{attempts}); retrying...",
                    file=sys.stderr,
                )
                if sleep_after_error and error_sleep_seconds > 0:
                    time.sleep(error_sleep_seconds)
                continue
            print(f"[!] Request timed out after {attempts} attempts.", file=sys.stderr)
            if sleep_after_error and error_sleep_seconds > 0:
                time.sleep(error_sleep_seconds)
            return None
        except requests.exceptions.RequestException as exc:
            print(f"[!] Unexpected request error: {exc}", file=sys.stderr)
            if sleep_after_error and error_sleep_seconds > 0:
                time.sleep(error_sleep_seconds)
            return None
    return None
