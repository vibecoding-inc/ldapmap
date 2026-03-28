from unittest.mock import MagicMock, patch
from urllib.parse import quote

import ldapmap

from tests.helpers import make_response


class TestBuildSession:
    def test_no_proxy(self):
        session = ldapmap.build_session(None)
        assert session is not None
        assert session.proxies == {}

    def test_with_proxy(self):
        session = ldapmap.build_session("http://127.0.0.1:8080")
        assert session.proxies["http"] == "http://127.0.0.1:8080"
        assert session.proxies["https"] == "http://127.0.0.1:8080"
        assert session.verify is False


class TestBuildPayloadData:
    def test_replaces_param(self):
        base = {"user": "admin", "pass": "secret"}
        result = ldapmap.build_payload_data(base, "pass", ")(uid=*)")
        assert result["pass"] != "secret"
        assert base["pass"] == "secret"

    def test_url_encodes_injection(self):
        base = {"p": "x"}
        result = ldapmap.build_payload_data(base, "p", ")(uid=*)")
        expected = quote(")(uid=*)", safe="")
        assert result["p"] == expected

    def test_other_params_unchanged(self):
        base = {"user": "admin", "pass": "secret"}
        result = ldapmap.build_payload_data(base, "pass", "*")
        assert result["user"] == "admin"

    def test_json_mode_no_url_encoding(self):
        base = {"user": "admin", "pass": "x"}
        result = ldapmap.build_payload_data(base, "pass", ")(uid=*)", use_json=True)
        assert result["pass"] == ")(uid=*)"

    def test_json_mode_does_not_mutate_original(self):
        base = {"user": "admin", "pass": "x"}
        ldapmap.build_payload_data(base, "pass", "injected", use_json=True)
        assert base["pass"] == "x"


class TestSendRequest:
    def test_successful_request(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"ok")
        resp = ldapmap.send_request(session, "http://example.com", {"a": "b"})
        assert resp is not None
        assert resp.status_code == 200

    def test_connection_error_returns_none(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.ConnectionError("err")
        resp = ldapmap.send_request(session, "http://example.com", {})
        assert resp is None

    def test_timeout_returns_none(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.Timeout()
        resp = ldapmap.send_request(session, "http://example.com", {})
        assert resp is None
        assert session.post.call_count == ldapmap.TIMEOUT_RETRIES + 1

    def test_generic_request_exception_returns_none(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.RequestException("err")
        resp = ldapmap.send_request(session, "http://example.com", {})
        assert resp is None

    def test_verbose_prints_payload(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"ok")
        with patch("builtins.print") as mock_print:
            ldapmap.send_request(
                session, "http://example.com", {"user": "admin", "pass": "x"},
                verbose=True,
            )
        verbose_calls = [
            c for c in mock_print.call_args_list
            if c.args and isinstance(c.args[0], str)
            and c.args[0].startswith("[V] POST http://example.com")
        ]
        assert verbose_calls

    def test_verbose_prints_http_status(self):
        session = MagicMock()
        session.post.return_value = make_response(201, b"created")
        with patch("builtins.print") as mock_print:
            ldapmap.send_request(session, "http://example.com", {"a": "b"}, verbose=True)
        status_calls = [
            c for c in mock_print.call_args_list
            if c.args and c.args[0] == "[V] HTTP 201"
        ]
        assert status_calls

    def test_non_verbose_prints_nothing_extra(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"ok")
        with patch("builtins.print") as mock_print:
            ldapmap.send_request(session, "http://example.com", {"a": "b"})
        mock_print.assert_not_called()

    def test_form_mode_uses_data_kwarg(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"ok")
        ldapmap.send_request(session, "http://example.com", {"a": "b"}, use_json=False)
        session.post.assert_called_once_with(
            "http://example.com", data={"a": "b"}, timeout=ldapmap.TIMEOUT
        )

    def test_json_mode_uses_json_kwarg(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"ok")
        ldapmap.send_request(session, "http://example.com", {"a": "b"}, use_json=True)
        session.post.assert_called_once_with(
            "http://example.com", json={"a": "b"}, timeout=ldapmap.TIMEOUT
        )

    def test_custom_timeout_is_forwarded(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"ok")
        ldapmap.send_request(session, "http://example.com", {"a": "b"}, timeout=1.5)
        session.post.assert_called_once_with(
            "http://example.com", data={"a": "b"}, timeout=1.5
        )

    def test_timeout_retry_then_success(self):
        session = MagicMock()
        session.post.side_effect = [
            ldapmap.requests.exceptions.Timeout(),
            make_response(200, b"ok"),
        ]
        resp = ldapmap.send_request(
            session,
            "http://example.com",
            {"a": "b"},
            timeout_retries=2,
            sleep_after_error=False,
        )
        assert resp is not None
        assert resp.status_code == 200
        assert session.post.call_count == 2

    def test_sleep_after_error_on_timeout_retry(self):
        session = MagicMock()
        session.post.side_effect = [
            ldapmap.requests.exceptions.Timeout(),
            make_response(200, b"ok"),
        ]
        with patch("ldapmap_http.time.sleep") as mock_sleep:
            ldapmap.send_request(
                session,
                "http://example.com",
                {"a": "b"},
                timeout_retries=2,
                sleep_after_error=True,
                error_sleep_seconds=2,
            )
        mock_sleep.assert_called_once_with(2)
