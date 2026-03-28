from unittest.mock import MagicMock

import ldapmap

from tests.helpers import make_response


class TestExtractAttribute:
    def test_extracts_known_value(self):
        target = "ab"
        session = MagicMock()

        def side_effect(url, data, timeout):
            from urllib.parse import unquote
            param_val = data.get("p", "")
            decoded = unquote(param_val)
            marker = "userPassword="
            if marker in decoded:
                after = decoded[decoded.index(marker) + len(marker):]
                if after.endswith("*)"):
                    candidate = after[:-2]
                else:
                    candidate = after
                if target.startswith(candidate) and candidate:
                    return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 999)

        session.post.side_effect = side_effect

        result = ldapmap.extract_attribute(
            session, "http://x", {"p": "v"}, "p", "userPassword", 200, 100
        )
        assert result == target

    def test_returns_empty_when_no_match(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"z" * 999)
        result = ldapmap.extract_attribute(
            session, "http://x", {"p": "v"}, "p", "userPassword", 200, 100
        )
        assert result == ""
