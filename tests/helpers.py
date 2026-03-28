from unittest.mock import MagicMock


def make_response(status_code: int, content: bytes) -> MagicMock:
    """Return a mock requests.Response with the given status and content."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content
    return resp
