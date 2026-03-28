"""CLI argument parsing for ldapmap."""

import argparse

from ldapmap_constants import CHARSET, ERROR_SLEEP_SECONDS, TIMEOUT, TIMEOUT_RETRIES


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


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
        "--extract-filter",
        metavar="FILTER",
        action="append",
        default=None,
        dest="extract_filters",
        help=(
            "Additional LDAP filter constraint for extraction (repeatable), "
            "e.g. --extract-filter uid=admin to extract an attribute for a "
            "specific user."
        ),
    )
    parser.add_argument(
        "--extract-charset",
        metavar="CHARS",
        default=CHARSET,
        help=(
            "Character set used during blind extraction probes. "
            "Defaults to built-in charset."
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
        "--timeout",
        metavar="SECONDS",
        type=_positive_float,
        default=TIMEOUT,
        help=f"HTTP request timeout in seconds (default: {TIMEOUT}).",
    )
    parser.add_argument(
        "--timeout-retries",
        metavar="COUNT",
        type=_non_negative_int,
        default=TIMEOUT_RETRIES,
        help=f"Additional retries after timeout errors (default: {TIMEOUT_RETRIES}).",
    )
    parser.add_argument(
        "--error-sleep-seconds",
        metavar="SECONDS",
        type=_non_negative_int,
        default=ERROR_SLEEP_SECONDS,
        help=f"Sleep time after request errors in seconds (default: {ERROR_SLEEP_SECONDS}).",
    )
    parser.add_argument(
        "--no-sleep-after-error",
        action="store_false",
        dest="sleep_after_error",
        default=True,
        help="Disable sleeping after request errors.",
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
