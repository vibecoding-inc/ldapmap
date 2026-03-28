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
                if after.endswith("*)(userPassword="):
                    candidate = after[:-16]
                elif after.endswith("*)("):
                    candidate = after[:-3]
                elif after.endswith("*)"):
                    candidate = after[:-2]
                elif "*" in after:
                    candidate = after.rsplit("*", 1)[0]
                else:
                    candidate = after
                if target.startswith(candidate):
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

    def test_extracts_with_fallback_template(self):
        target = "ab"
        session = MagicMock()

        def side_effect(url, data, timeout):
            from urllib.parse import unquote
            decoded = unquote(data.get("p", ""))
            marker = "userPassword="
            if marker not in decoded:
                return make_response(200, b"y" * 999)

            # Only accept the second template: )(attr=<prefix>*)(attr=
            if "*)(userPassword=" not in decoded:
                return make_response(200, b"y" * 999)

            after = decoded[decoded.index(marker) + len(marker):]
            if after.endswith("*)(userPassword="):
                candidate = after[:-16]
            elif after.endswith("*)("):
                candidate = after[:-3]
            elif after.endswith("*)"):
                candidate = after[:-2]
            elif "*" in after:
                candidate = after.rsplit("*", 1)[0]
            else:
                candidate = after
            if target.startswith(candidate):
                return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 999)

        session.post.side_effect = side_effect
        result = ldapmap.extract_attribute(
            session, "http://x", {"p": "v"}, "p", "userPassword", 200, 100
        )
        assert result == target
