from unittest.mock import MagicMock, patch
from urllib.parse import quote

import ldapmap

from tests.helpers import make_response


class TestGetBaseline:
    def test_returns_status_and_length(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"hello")
        status, length = ldapmap.get_baseline(session, "http://x", {"p": "v"})
        assert status == 200
        assert length == 5

    def test_exits_on_none_response(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.ConnectionError()
        try:
            ldapmap.get_baseline(session, "http://x", {})
            assert False, "Expected SystemExit"
        except SystemExit:
            pass


class TestCalibrate:
    def test_same_as_baseline_keeps_baseline(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"x" * 100)
        status, length = ldapmap.calibrate(session, "http://x", {"p": "v"}, "p", 200, 100)
        assert status == 200
        assert length == 100

    def test_different_from_baseline_uses_wildcard(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"x" * 800)
        status, length = ldapmap.calibrate(session, "http://x", {"p": "v"}, "p", 200, 100)
        assert length == 800

    def test_none_response_returns_original(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.Timeout()
        status, length = ldapmap.calibrate(session, "http://x", {"p": "v"}, "p", 200, 100)
        assert status == 200
        assert length == 100


class TestDetectInjection:
    def test_detects_when_payload_differs(self):
        session = MagicMock()

        def side_effect(url, data, timeout):
            if "(" in str(data.get("p", "")):
                return make_response(500, b"error")
            return make_response(200, b"ok" * 50)

        session.post.side_effect = side_effect
        result = ldapmap.detect_injection(
            session, "http://x", {"p": "v"}, "p", 200, 100
        )
        assert result is True

    def test_marks_vulnerable_when_logic_probe_matches_true(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"x" * 100)
        result = ldapmap.detect_injection(
            session, "http://x", {"p": "v"}, "p", 200, 100
        )
        assert result is True

    def test_probe_attr_used_in_payloads(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"x" * 100)
        seen_payloads = []

        original_build = ldapmap.build_payload_data

        def capture_build(base_data, param, injection, use_json=False):
            seen_payloads.append(injection)
            return original_build(base_data, param, injection, use_json)

        with patch.object(ldapmap, "build_payload_data", side_effect=capture_build):
            ldapmap.detect_injection(
                session, "http://x", {"p": "v"}, "p", 200, 100,
                probe_attr="uid",
            )

        probe_payloads = [p for p in seen_payloads if "uid" in p]
        assert probe_payloads
        for payload in seen_payloads:
            assert "objectClass" not in payload


class TestDiscoverAttributes:
    def test_returns_matching_attributes(self):
        session = MagicMock()

        def side_effect(url, data, timeout):
            param_val = data.get("p", "")
            if "uid" in param_val or "mail" in param_val:
                return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 300)

        session.post.side_effect = side_effect
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100
        )
        assert "uid" in found
        assert "mail" in found

    def test_returns_empty_when_nothing_matches(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"z" * 999)
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100
        )
        assert found == []

    def test_uses_custom_attributes_list(self):
        session = MagicMock()
        custom_attrs = ["customAttr1", "customAttr2"]

        def side_effect(url, data, timeout):
            param_val = data.get("p", "")
            if "customAttr1" in param_val:
                return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 300)

        session.post.side_effect = side_effect
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100,
            attributes=custom_attrs,
        )
        assert found == ["customAttr1"]
        assert session.post.call_count == 4

    def test_none_attributes_falls_back_to_common(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"z" * 999)
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100,
            attributes=None,
        )
        assert found == []
        assert session.post.call_count == len(ldapmap.COMMON_ATTRIBUTES) * 3

    def test_payload_appends_opening_bracket_for_next_parameter(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"z" * 999)

        ldapmap.discover_attributes(session, "http://x", {"p": "v"}, "p", 200, 100)

        first_payload = session.post.call_args_list[0].kwargs["data"]["p"]
        expected = quote(")(uid=*)(", safe="")
        assert first_payload == expected

    def test_checks_both_payload_variations(self):
        session = MagicMock()

        def side_effect(url, data, timeout):
            param_val = data.get("p", "")
            if param_val == quote(")(uid=*)(uid=", safe=""):
                return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 300)

        session.post.side_effect = side_effect
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100, attributes=["uid"]
        )
        assert found == ["uid"]
        assert session.post.call_count == 2
        first_payload = session.post.call_args_list[0].kwargs["data"]["p"]
        second_payload = session.post.call_args_list[1].kwargs["data"]["p"]
        assert first_payload == quote(")(uid=*)(", safe="")
        assert second_payload == quote(")(uid=*)(uid=", safe="")

    def test_checks_third_payload_variation(self):
        session = MagicMock()

        def side_effect(url, data, timeout):
            param_val = data.get("p", "")
            if param_val == quote(")(uid=*)", safe=""):
                return make_response(200, b"x" * 100)
            return make_response(200, b"y" * 300)

        session.post.side_effect = side_effect
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100, attributes=["uid"]
        )
        assert found == ["uid"]
        assert session.post.call_count == 3
        first_payload = session.post.call_args_list[0].kwargs["data"]["p"]
        second_payload = session.post.call_args_list[1].kwargs["data"]["p"]
        third_payload = session.post.call_args_list[2].kwargs["data"]["p"]
        assert first_payload == quote(")(uid=*)(", safe="")
        assert second_payload == quote(")(uid=*)(uid=", safe="")
        assert third_payload == quote(")(uid=*)", safe="")
