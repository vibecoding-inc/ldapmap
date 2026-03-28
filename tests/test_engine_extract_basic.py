from unittest.mock import MagicMock
from urllib.parse import unquote

import ldapmap

from tests.helpers import extract_candidate_from_data, make_response


class TestExtractAttributeBasic:
    def test_extracts_known_value(self):
        target = "ab"
        session = MagicMock()

        def side_effect(url, data, timeout):
            decoded = unquote(data.get("p", ""))
            candidate = extract_candidate_from_data(data, "userPassword=")
            if candidate is None:
                return make_response(200, b"y" * 999)
            if decoded.endswith("*)(userPassword="):
                return make_response(200, b"y" * 999)
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
            decoded = unquote(data.get("p", ""))
            if "*)(userPassword=" not in decoded:
                return make_response(200, b"y" * 999)
            candidate = extract_candidate_from_data(data, "userPassword=")
            if candidate is not None and target.startswith(candidate):
                return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 999)

        session.post.side_effect = side_effect
        result = ldapmap.extract_attribute(
            session, "http://x", {"p": "v"}, "p", "userPassword", 200, 100
        )
        assert result == target

    def test_excludes_specific_value(self):
        target = "ab"
        session = MagicMock()

        def side_effect(url, data, timeout):
            candidate = extract_candidate_from_data(data, "userPassword=")
            if candidate is not None and target.startswith(candidate):
                return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 999)

        session.post.side_effect = side_effect
        result = ldapmap.extract_attribute(
            session,
            "http://x",
            {"p": "v"},
            "p",
            "userPassword",
            200,
            100,
            exclude_value="ab",
        )
        assert result == ""

    def test_extract_with_manual_filter_constraints(self):
        target = "123"
        session = MagicMock()

        def side_effect(url, data, timeout):
            decoded = unquote(data.get("p", ""))
            if "(uid=admin)" not in decoded:
                return make_response(200, b"y" * 999)
            candidate = extract_candidate_from_data(data, "telephoneNumber=")
            if candidate is not None and target.startswith(candidate):
                return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 999)

        session.post.side_effect = side_effect
        result = ldapmap.extract_attribute(
            session,
            "http://x",
            {"p": "v"},
            "p",
            "telephoneNumber",
            200,
            100,
            extraction_filters=["uid=admin"],
        )
        assert result == target

    def test_extract_filter_validation_error(self):
        session = MagicMock()
        try:
            ldapmap.extract_attribute(
                session,
                "http://x",
                {"p": "v"},
                "p",
                "uid",
                200,
                100,
                extraction_filters=["uidadmin"],
            )
            assert False, "Expected ValueError"
        except ValueError:
            pass

    def test_extract_uses_custom_charset(self):
        session = MagicMock()

        def side_effect(url, data, timeout):
            decoded = unquote(data.get("p", ""))
            candidate = extract_candidate_from_data(data, "uid=")
            if candidate is None:
                return make_response(200, b"y" * 999)

            if "*" in decoded and candidate in {"", "3"}:
                return make_response(200, b"x" * 100)
            if "*" not in decoded and candidate == "3":
                return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 999)

        session.post.side_effect = side_effect
        result = ldapmap.extract_attribute(
            session,
            "http://x",
            {"p": "v"},
            "p",
            "uid",
            200,
            100,
            charset="3",
        )
        assert result == "3"
