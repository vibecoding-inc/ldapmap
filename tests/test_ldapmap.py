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

    def test_json_mode_no_url_encoding(self):
        base = {"user": "admin", "pass": "x"}
        result = ldapmap.build_payload_data(base, "pass", ")(uid=*)", use_json=True)
        # Raw injection string must be preserved without URL encoding
        self.assertEqual(result["pass"], ")(uid=*)")

    def test_json_mode_does_not_mutate_original(self):
        base = {"user": "admin", "pass": "x"}
        ldapmap.build_payload_data(base, "pass", "injected", use_json=True)
        self.assertEqual(base["pass"], "x")


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

    # ------------------------------------------------------------------
    # Explicit code-based classification
    # ------------------------------------------------------------------

    def test_true_codes_matching_returns_true(self):
        """Status code in true_codes → True regardless of length."""
        resp = make_response(200, b"x" * 999)  # length differs from baseline
        result = ldapmap.is_true_response(resp, 200, 100, true_codes={200}, false_codes={401})
        self.assertIs(result, True)

    def test_false_codes_matching_returns_false(self):
        """Status code in false_codes → False."""
        resp = make_response(401, b"x" * 100)
        result = ldapmap.is_true_response(resp, 200, 100, true_codes={200}, false_codes={401})
        self.assertIs(result, False)

    def test_unknown_code_returns_none(self):
        """Status code in neither set → None (error, not FALSE)."""
        resp = make_response(500, b"server error")
        result = ldapmap.is_true_response(resp, 200, 100, true_codes={200}, false_codes={401})
        self.assertIsNone(result)

    def test_only_true_codes_specified_unknown_is_none(self):
        """With only true_codes set, non-matching status → None."""
        resp = make_response(403, b"forbidden")
        result = ldapmap.is_true_response(resp, 200, 100, true_codes={200})
        self.assertIsNone(result)

    def test_only_false_codes_specified_unknown_is_none(self):
        """With only false_codes set, non-matching status → None."""
        resp = make_response(200, b"ok" * 100)
        result = ldapmap.is_true_response(resp, 200, 100, false_codes={401})
        self.assertIsNone(result)

    def test_none_response_with_codes_still_false(self):
        """resp=None always returns False even when codes are specified."""
        result = ldapmap.is_true_response(None, 200, 500, true_codes={200}, false_codes={401})
        self.assertFalse(result)


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

    def test_verbose_prints_payload(self):
        """When verbose=True, send_request should print the URL, POST data, and response status."""
        session = MagicMock()
        session.post.return_value = make_response(200, b"ok")
        with patch("builtins.print") as mock_print:
            ldapmap.send_request(
                session, "http://example.com", {"user": "admin", "pass": "x"},
                verbose=True,
            )
        all_messages = [
            c.args[0] for c in mock_print.call_args_list
            if c.args and isinstance(c.args[0], str)
        ]
        # At least one print call must start with "[V] POST <url>"
        self.assertTrue(
            any(m.startswith("[V] POST http://example.com") for m in all_messages),
            "Expected a [V] verbose log line for the request",
        )
        # At least one print call must include the response status code
        self.assertTrue(
            any("HTTP 200" in m for m in all_messages),
            "Expected a [V] verbose log line containing the response status code",
        )

    def test_non_verbose_prints_nothing_extra(self):
        """When verbose=False (default), send_request must not produce output."""
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

    def test_probe_attr_used_in_payloads(self):
        """
        When probe_attr is supplied, the injected payloads should reference
        that attribute instead of the default 'objectClass'.
        """
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
        self.assertTrue(probe_payloads, "Expected at least one payload containing 'uid'")
        # None of the payloads should still reference 'objectClass'
        for p in seen_payloads:
            self.assertNotIn("objectClass", p)


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

    def test_uses_custom_attributes_list(self):
        """
        When a custom attributes list is passed, only those attributes are
        probed (not the built-in COMMON_ATTRIBUTES).
        """
        session = MagicMock()
        custom_attrs = ["customAttr1", "customAttr2"]

        def side_effect(url, data, timeout):
            param_val = data.get("p", "")
            if "customAttr1" in param_val:
                return make_response(200, b"x" * 100)  # true
            return make_response(200, b"y" * 300)  # false

        session.post.side_effect = side_effect
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100,
            attributes=custom_attrs,
        )
        self.assertEqual(found, ["customAttr1"])
        # Verify only the custom attrs were probed (2 requests)
        self.assertEqual(session.post.call_count, len(custom_attrs))

    def test_none_attributes_falls_back_to_common(self):
        """Passing attributes=None should behave identically to the default."""
        session = MagicMock()
        session.post.return_value = make_response(200, b"z" * 999)
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100,
            attributes=None,
        )
        self.assertEqual(found, [])
        # One request per attribute in COMMON_ATTRIBUTES
        self.assertEqual(session.post.call_count, len(ldapmap.COMMON_ATTRIBUTES))

    def test_payload_contains_opening_bracket_for_next_param(self):
        """
        The discovery payload must end with '(' so that the opening bracket
        for the next LDAP parameter is present, keeping the filter balanced.
        """
        session = MagicMock()
        session.post.return_value = make_response(200, b"x" * 100)
        seen_payloads = []

        original_build = ldapmap.build_payload_data

        def capture_build(base_data, param, injection, use_json=False):
            seen_payloads.append(injection)
            return original_build(base_data, param, injection, use_json)

        with patch.object(ldapmap, "build_payload_data", side_effect=capture_build):
            ldapmap.discover_attributes(
                session, "http://x", {"p": "v"}, "p", 200, 100,
                attributes=["uid"],
            )

        self.assertEqual(len(seen_payloads), 1)
        payload = seen_payloads[0]
        self.assertTrue(
            payload.endswith("("),
            f"Discovery payload should end with '(' but got: {payload!r}",
        )

    def test_error_code_not_counted_as_absent(self):
        """
        When an explicit true/false code is set, a response with an unexpected
        status code should be treated as an error, not as absent (FALSE).
        """
        session = MagicMock()
        # All responses return 500 — neither in true_codes nor false_codes
        session.post.return_value = make_response(500, b"server error")
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100,
            attributes=["uid"],
            true_codes={200},
            false_codes={401},
        )
        # 500 is an error, not FALSE → attribute should NOT appear in found
        # AND should not be silently counted as absent (just skipped)
        self.assertEqual(found, [])

    def test_true_code_marks_attribute_present(self):
        """A response whose status is in true_codes marks the attribute as present."""
        session = MagicMock()
        session.post.return_value = make_response(200, b"x" * 999)  # length differs
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100,
            attributes=["uid"],
            true_codes={200},
            false_codes={401},
        )
        self.assertIn("uid", found)

    def test_false_code_marks_attribute_absent(self):
        """A response whose status is in false_codes marks the attribute as absent."""
        session = MagicMock()
        session.post.return_value = make_response(401, b"unauthorized")
        found = ldapmap.discover_attributes(
            session, "http://x", {"p": "v"}, "p", 200, 100,
            attributes=["uid"],
            true_codes={200},
            false_codes={401},
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
        self.assertIsNone(args.attributes)

    def test_optional_proxy(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a",
                            "--proxy", "http://127.0.0.1:8080"])
        self.assertEqual(args.proxy, "http://127.0.0.1:8080")

    def test_optional_extract(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a",
                            "--extract", "userPassword"])
        self.assertEqual(args.extract, "userPassword")

    def test_verbose_flag_short(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a", "-v"])
        self.assertTrue(args.verbose)

    def test_verbose_flag_long(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a", "--verbose"])
        self.assertTrue(args.verbose)

    def test_verbose_defaults_to_false(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a"])
        self.assertFalse(args.verbose)

    def test_missing_required_exits(self):
        with self.assertRaises(SystemExit):
            self._parse(["-u", "http://x"])  # missing -d/-jsondata and -p

    def test_jsondata_arg(self):
        args = self._parse(["-u", "http://x", "--jsondata", '{"a":"b"}', "-p", "a"])
        self.assertIsNone(args.data)
        self.assertEqual(args.jsondata, '{"a":"b"}')
        self.assertEqual(args.param, "a")

    def test_data_and_jsondata_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            self._parse([
                "-u", "http://x", "-d", "a=b",
                "--jsondata", '{"a":"b"}', "-p", "a",
            ])

    def test_data_sets_jsondata_to_none(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a"])
        self.assertIsNone(args.jsondata)

    def test_attributes_single(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a",
                            "--attributes", "uid"])
        self.assertEqual(args.attributes, ["uid"])

    def test_attributes_multiple(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a",
                            "--attributes", "uid", "--attributes", "cn"])
        self.assertEqual(args.attributes, ["uid", "cn"])

    def test_attributes_defaults_to_none(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a"])
        self.assertIsNone(args.attributes)


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

    @patch("ldapmap.build_session")
    def test_main_invalid_json_exits(self, mock_build_session):
        """Invalid JSON in --jsondata must exit with an error."""
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "--jsondata", "not-valid-json", "-p", "pass"
        ]):
            with self.assertRaises(SystemExit):
                ldapmap.main()

    @patch("ldapmap.build_session")
    def test_main_jsondata_non_object_exits(self, mock_build_session):
        """--jsondata must be a JSON object, not an array or scalar."""
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "--jsondata", '["a","b"]', "-p", "a"
        ]):
            with self.assertRaises(SystemExit):
                ldapmap.main()

    @patch("ldapmap.build_session")
    def test_main_missing_param_in_jsondata_exits(self, mock_build_session):
        """If --param isn't a key in --jsondata, main() must exit with an error."""
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x",
            "--jsondata", '{"username":"","email":""}', "-p", "password"
        ]):
            with self.assertRaises(SystemExit):
                ldapmap.main()

    @patch("ldapmap.discover_attributes", return_value=["uid"])
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_jsondata_discovery_path(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_discover
    ):
        """main() with --jsondata should invoke discover_attributes with use_json=True."""
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x",
            "--jsondata", '{"username":"","email":"INJECT_HERE"}',
            "-p", "email",
        ]):
            ldapmap.main()
        mock_discover.assert_called_once()
        # Verify use_json=True was forwarded to discover_attributes
        args_positional = mock_discover.call_args[0]
        # discover_attributes(session, url, base_data, param, true_status, true_length, verbose, use_json)
        self.assertEqual(args_positional[7], True)

    @patch("ldapmap.extract_attribute", return_value="user@example.com")
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_jsondata_extract_path(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_extract
    ):
        """main() with --jsondata and --extract should call extract_attribute."""
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x",
            "--jsondata", '{"username":"","email":"INJECT_HERE"}',
            "-p", "email", "--extract", "mail",
        ]):
            ldapmap.main()
        mock_extract.assert_called_once()
        args_positional = mock_extract.call_args[0]
        # extract_attribute(session, url, base_data, param, attribute, true_status, true_length, verbose, use_json)
        self.assertEqual(args_positional[8], True)


    @patch("ldapmap.discover_attributes", return_value=["uid"])
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_attributes_forwarded_to_discover(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_discover
    ):
        """--attributes should extend the attribute list passed to discover_attributes
        and set the probe_attr for detect_injection."""
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "-d", "user=admin&pass=x",
            "-p", "pass", "--attributes", "uid", "--attributes", "cn",
        ]):
            ldapmap.main()

        mock_discover.assert_called_once()
        # The attributes list passed to discover_attributes should start with
        # the user-supplied ones and include the built-in COMMON_ATTRIBUTES too.
        call_args = mock_discover.call_args[0]
        # attributes is the 9th positional arg (index 8)
        attr_list = call_args[8]
        self.assertIn("uid", attr_list)
        self.assertIn("cn", attr_list)
        # Extra attrs should appear before the built-in ones
        self.assertLess(attr_list.index("uid"), attr_list.index("mail"))

        # detect_injection receives probe_attr as first extra-supplied attribute
        detect_call_args = mock_detect.call_args[0]
        # detect_injection(session, url, base_data, param, true_status, true_length, verbose, use_json, probe_attr)
        self.assertEqual(detect_call_args[8], "uid")

    @patch("ldapmap.discover_attributes", return_value=[])
    @patch("ldapmap.detect_injection", return_value=False)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_no_attributes_uses_objectclass_probe(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_discover
    ):
        """Without --attributes, detect_injection should default to 'objectClass'."""
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "-d", "user=admin&pass=x", "-p", "pass",
        ]):
            ldapmap.main()

        detect_call_args = mock_detect.call_args[0]
        # probe_attr is at index 8
        self.assertEqual(detect_call_args[8], "objectClass")


if __name__ == "__main__":
    unittest.main()
