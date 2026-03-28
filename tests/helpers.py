from unittest.mock import MagicMock
from urllib.parse import unquote


def make_response(status_code: int, content: bytes) -> MagicMock:
    """Return a mock requests.Response with the given status and content."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content
    return resp


def extract_candidate(decoded_value: str, marker: str) -> str | None:
    """Extract candidate value from a decoded LDAP payload.

    Args:
        decoded_value: URL-decoded injected LDAP filter fragment.
        marker: Attribute marker to locate, e.g. ``"uid="``.
    """
    if marker not in decoded_value:
        return None

    after = decoded_value[decoded_value.index(marker) + len(marker):]
    if after.endswith("*)("):
        return after[:-3]
    if after.endswith("*)"):
        return after[:-2]
    if "*" in after:
        return after.rsplit("*", 1)[0]
    return after


def extract_candidate_from_data(data: dict, marker: str) -> str | None:
    """Decode posted data and extract candidate probe fragment.

    Args:
        data: Request data dictionary containing injectable ``"p"`` value.
        marker: Attribute marker to locate, e.g. ``"userPassword="``.
    """
    decoded = unquote(data.get("p", ""))
    return extract_candidate(decoded, marker)
