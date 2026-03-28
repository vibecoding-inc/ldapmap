"""
Unit tests for ldapmap.py

These tests mock the network layer so no real HTTP server is required.
Run with:
    pip install pytest requests
    pytest tests/test_ldapmap.py -v
"""

import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch, call
from urllib.parse import parse_qs, quote

# Make sure the repo root is on the path so we can import ldapmap
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import ldapmap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_response(status_code: int, content: bytes) -> MagicMock:
    """Return a mock requests.Response with the given status and content."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content
    return resp


# ---------------------------------------------------------------------------
# Tests: build_session
# ---------------------------------------------------------------------------


class TestBuildSession(unittest.TestCase):
    def test_no_proxy(self):
        session = ldapmap.build_session(None)
        self.assertIsNotNone(session)
        self.assertEqual(session.proxies, {})

    def test_with_proxy(self):
        session = ldapmap.build_session("http://127.0.0.1:8080")
        self.assertEqual(session.proxies["http"], "http://127.0.0.1:8080")
        self.assertEqual(session.proxies["https"], "http://127.0.0.1:8080")
        self.assertFalse(session.verify)


# ---------------------------------------------------------------------------
# Tests: build_payload_data
# ---------------------------------------------------------------------------


class TestBuildPayloadData(unittest.TestCase):
    def test_replaces_param(self):
        base = {"user": "admin", "pass": "secret"}
        result = ldapmap.build_payload_data(base, "pass", ")(uid=*)")
        self.assertNotEqual(result["pass"], "secret")
        # Original dict must not be mutated
        self.assertEqual(base["pass"], "secret")

    def test_url_encodes_injection(self):
        base = {"p": "x"}
        result = ldapmap.build_payload_data(base, "p", ")(uid=*)")
        # quote() should have encoded the special chars
        expected = quote(")(uid=*)", safe="")
        self.assertEqual(result["p"], expected)

    def test_other_params_unchanged(self):
        base = {"user": "admin", "pass": "secret"}
        result = ldapmap.build_payload_data(base, "pass", "*")
        self.assertEqual(result["user"], "admin")


# ---------------------------------------------------------------------------
# Tests: is_true_response
# ---------------------------------------------------------------------------


class TestIsTrueResponse(unittest.TestCase):
    def test_none_response_is_false(self):
        self.assertFalse(ldapmap.is_true_response(None, 200, 500))

    def test_matching_response_is_true(self):
        resp = make_response(200, b"x" * 500)
        self.assertTrue(ldapmap.is_true_response(resp, 200, 500))

    def test_within_tolerance_is_true(self):
        resp = make_response(200, b"x" * (500 + ldapmap.LENGTH_TOLERANCE))
        self.assertTrue(ldapmap.is_true_response(resp, 200, 500))

    def test_outside_tolerance_is_false(self):
        resp = make_response(200, b"x" * (500 + ldapmap.LENGTH_TOLERANCE + 1))
        self.assertFalse(ldapmap.is_true_response(resp, 200, 500))

    def test_wrong_status_is_false(self):
        resp = make_response(302, b"x" * 500)
        self.assertFalse(ldapmap.is_true_response(resp, 200, 500))


# ---------------------------------------------------------------------------
# Tests: send_request
# ---------------------------------------------------------------------------


class TestSendRequest(unittest.TestCase):
    def test_successful_request(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"ok")
        resp = ldapmap.send_request(session, "http://example.com", {"a": "b"})
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)

    def test_connection_error_returns_none(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.ConnectionError("err")
        resp = ldapmap.send_request(session, "http://example.com", {})
        self.assertIsNone(resp)

    def test_timeout_returns_none(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.Timeout()
        resp = ldapmap.send_request(session, "http://example.com", {})
        self.assertIsNone(resp)

    def test_generic_request_exception_returns_none(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.RequestException("err")
        resp = ldapmap.send_request(session, "http://example.com", {})
        self.assertIsNone(resp)


# ---------------------------------------------------------------------------
# Tests: get_baseline
# ---------------------------------------------------------------------------


class TestGetBaseline(unittest.TestCase):
    def test_returns_status_and_length(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"hello")
        status, length = ldapmap.get_baseline(session, "http://x", {"p": "v"})
        self.assertEqual(status, 200)
        self.assertEqual(length, 5)

    def test_exits_on_none_response(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.ConnectionError()
        with self.assertRaises(SystemExit):
            ldapmap.get_baseline(session, "http://x", {})


# ---------------------------------------------------------------------------
# Tests: calibrate
# ---------------------------------------------------------------------------


class TestCalibrate(unittest.TestCase):
    def test_same_as_baseline_keeps_baseline(self):
        session = MagicMock()
        # Wildcard response identical to baseline
        session.post.return_value = make_response(200, b"x" * 100)
        status, length = ldapmap.calibrate(session, "http://x", {"p": "v"}, "p", 200, 100)
        self.assertEqual(status, 200)
        self.assertEqual(length, 100)

    def test_different_from_baseline_uses_wildcard(self):
        session = MagicMock()
        # Wildcard response differs (e.g. application shows "logged in" page)
        session.post.return_value = make_response(200, b"x" * 800)
        status, length = ldapmap.calibrate(session, "http://x", {"p": "v"}, "p", 200, 100)
        self.assertEqual(length, 800)

    def test_none_response_returns_original(self):
        session = MagicMock()
        session.post.side_effect = ldapmap.requests.exceptions.Timeout()
        status, length = ldapmap.calibrate(session, "http://x", {"p": "v"}, "p", 200, 100)
        self.assertEqual(status, 200)
        self.assertEqual(length, 100)


# ---------------------------------------------------------------------------
# Tests: detect_injection
# ---------------------------------------------------------------------------


class TestDetectInjection(unittest.TestCase):
    def test_detects_when_payload_differs(self):
        session = MagicMock()

        def side_effect(url, data, timeout):
            # Make the first special-char payload return a different response
            if "(" in str(data.get("p", "")):
                return make_response(500, b"error")
            return make_response(200, b"ok" * 50)

        session.post.side_effect = side_effect
        result = ldapmap.detect_injection(
            session, "http://x", {"p": "v"}, "p", 200, 100
        )
        self.assertTrue(result)

    def test_marks_vulnerable_when_logic_probe_matches_true(self):
        """
        If every response (including logic probes) looks like the TRUE signature,
        detect_injection should report vulnerable=True.  This happens when, for
        example, an OR-context injection returns 'true' for the OR_true probe.
        """
        session = MagicMock()
        # Every response matches the true signature → logic probes look "true"
        session.post.return_value = make_response(200, b"x" * 100)
        result = ldapmap.detect_injection(
            session, "http://x", {"p": "v"}, "p", 200, 100
        )
        self.assertTrue(result)


# ---------------------------------------------------------------------------
# Tests: discover_attributes
# ---------------------------------------------------------------------------


class TestDiscoverAttributes(unittest.TestCase):
    def test_returns_matching_attributes(self):
        session = MagicMock()
        # Only 'uid' and 'mail' wildcard payloads return a true response
        def side_effect(url, data, timeout):
            param_val = data.get("p", "")
            if "uid" in param_val or "mail" in param_val:
                return make_response(200, b"x" * 100)  # true
            return make_response(200, b"y" * 300)  # false (different length)

        session.post.side_effect = side_effect
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100
        )
        self.assertIn("uid", found)
        self.assertIn("mail", found)

    def test_returns_empty_when_nothing_matches(self):
        session = MagicMock()
        session.post.return_value = make_response(200, b"z" * 999)
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100
        )
        self.assertEqual(found, [])


# ---------------------------------------------------------------------------
# Tests: extract_attribute
# ---------------------------------------------------------------------------


class TestExtractAttribute(unittest.TestCase):
    def test_extracts_known_value(self):
        """
        Simulate extracting the value 'ab'.
        The mock returns a true response only when the payload ends with
        the correct prefix character followed by '*'.
        """
        target = "ab"
        session = MagicMock()

        def side_effect(url, data, timeout):
            from urllib.parse import unquote
            param_val = data.get("p", "")
            decoded = unquote(param_val)
            marker = "userPassword="
            if marker in decoded:
                after = decoded[decoded.index(marker) + len(marker):]
                # The payload format is: )(attr=<prefix><char>*)
                # Strip exactly the trailing "*)" suffix to isolate the candidate.
                if after.endswith("*)"):
                    candidate = after[:-2]
                else:
                    candidate = after
                if target.startswith(candidate) and candidate:
                    return make_response(200, b"x" * 100)  # true
            return make_response(200, b"y" * 999)  # false

        session.post.side_effect = side_effect

        result = ldapmap.extract_attribute(
            session, "http://x", {"p": "v"}, "p", "userPassword", 200, 100
        )
        self.assertEqual(result, target)

    def test_returns_empty_when_no_match(self):
        session = MagicMock()
        # Always return a false response
        session.post.return_value = make_response(200, b"z" * 999)
        result = ldapmap.extract_attribute(
            session, "http://x", {"p": "v"}, "p", "userPassword", 200, 100
        )
        self.assertEqual(result, "")


# ---------------------------------------------------------------------------
# Tests: parse_args
# ---------------------------------------------------------------------------


class TestParseArgs(unittest.TestCase):
    def _parse(self, argv):
        with patch("sys.argv", ["ldapmap"] + argv):
            return ldapmap.parse_args()

    def test_required_args(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a"])
        self.assertEqual(args.url, "http://x")
        self.assertEqual(args.data, "a=b")
        self.assertEqual(args.param, "a")
        self.assertIsNone(args.proxy)
        self.assertIsNone(args.extract)

    def test_optional_proxy(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a",
                            "--proxy", "http://127.0.0.1:8080"])
        self.assertEqual(args.proxy, "http://127.0.0.1:8080")

    def test_optional_extract(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a",
                            "--extract", "userPassword"])
        self.assertEqual(args.extract, "userPassword")

    def test_missing_required_exits(self):
        with self.assertRaises(SystemExit):
            self._parse(["-u", "http://x"])  # missing -d and -p


# ---------------------------------------------------------------------------
# Tests: main() — integration-level smoke test
# ---------------------------------------------------------------------------


class TestMain(unittest.TestCase):
    @patch("ldapmap.build_session")
    def test_main_missing_param_exits(self, mock_build_session):
        """If --param isn't in --data, main() must exit with an error."""
        with patch("sys.argv", ["ldapmap", "-u", "http://x", "-d", "a=b", "-p", "z"]):
            with self.assertRaises(SystemExit):
                ldapmap.main()

    @patch("ldapmap.extract_attribute", return_value="secret")
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_extract_path(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_extract
    ):
        """main() with --extract should call extract_attribute."""
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "-d", "user=admin&pass=x",
            "-p", "pass", "--extract", "userPassword"
        ]):
            ldapmap.main()
        mock_extract.assert_called_once()

    @patch("ldapmap.discover_attributes", return_value=["uid", "mail"])
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_discovery_path(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_discover
    ):
        """main() without --extract should call discover_attributes."""
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "-d", "user=admin&pass=x", "-p", "pass"
        ]):
            ldapmap.main()
        mock_discover.assert_called_once()


if __name__ == "__main__":
    unittest.main()
