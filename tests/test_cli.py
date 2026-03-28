from unittest.mock import patch

import ldapmap


class TestParseArgs:
    def _parse(self, argv):
        with patch("sys.argv", ["ldapmap"] + argv):
            return ldapmap.parse_args()

    def test_required_args(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a"])
        assert args.url == "http://x"
        assert args.data == "a=b"
        assert args.param == "a"
        assert args.proxy is None
        assert args.extract is None
        assert args.attributes is None
        assert args.timeout == ldapmap.TIMEOUT
        assert args.timeout_retries == ldapmap.TIMEOUT_RETRIES
        assert args.sleep_after_error is True
        assert args.error_sleep_seconds == ldapmap.ERROR_SLEEP_SECONDS

    def test_optional_proxy(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a", "--proxy", "http://127.0.0.1:8080"])
        assert args.proxy == "http://127.0.0.1:8080"

    def test_optional_extract(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a", "--extract", "userPassword"])
        assert args.extract == "userPassword"

    def test_verbose_flag_short(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a", "-v"])
        assert args.verbose is True

    def test_verbose_flag_long(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a", "--verbose"])
        assert args.verbose is True

    def test_verbose_defaults_to_false(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a"])
        assert args.verbose is False

    def test_missing_required_exits(self):
        try:
            self._parse(["-u", "http://x"])
            assert False, "Expected SystemExit"
        except SystemExit:
            pass

    def test_jsondata_arg(self):
        args = self._parse(["-u", "http://x", "--jsondata", '{"a":"b"}', "-p", "a"])
        assert args.data is None
        assert args.jsondata == '{"a":"b"}'
        assert args.param == "a"

    def test_data_and_jsondata_mutually_exclusive(self):
        try:
            self._parse([
                "-u", "http://x", "-d", "a=b",
                "--jsondata", '{"a":"b"}', "-p", "a",
            ])
            assert False, "Expected SystemExit"
        except SystemExit:
            pass

    def test_data_sets_jsondata_to_none(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a"])
        assert args.jsondata is None

    def test_attributes_single(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a", "--attributes", "uid"])
        assert args.attributes == ["uid"]

    def test_attributes_multiple(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a", "--attributes", "uid", "--attributes", "cn"])
        assert args.attributes == ["uid", "cn"]

    def test_attributes_defaults_to_none(self):
        args = self._parse(["-u", "http://x", "-d", "a=b", "-p", "a"])
        assert args.attributes is None

    def test_true_status_repeatable(self):
        args = self._parse([
            "-u", "http://x", "-d", "a=b", "-p", "a",
            "--true-status", "200", "--true-status", "302",
        ])
        assert args.true_statuses == [200, 302]

    def test_false_status_repeatable(self):
        args = self._parse([
            "-u", "http://x", "-d", "a=b", "-p", "a",
            "--false-status", "401", "--false-status", "403",
        ])
        assert args.false_statuses == [401, 403]

    def test_exclude_value(self):
        args = self._parse([
            "-u", "http://x", "-d", "a=b", "-p", "a",
            "--exclude-value", "admin",
        ])
        assert args.exclude_value == "admin"

    def test_find_all_flag(self):
        args = self._parse([
            "-u", "http://x", "-d", "a=b", "-p", "a",
            "--find-all",
        ])
        assert args.find_all is True

    def test_extract_filter_repeatable(self):
        args = self._parse([
            "-u", "http://x", "-d", "a=b", "-p", "a",
            "--extract-filter", "uid=admin",
            "--extract-filter", "(cn=John)",
        ])
        assert args.extract_filters == ["uid=admin", "(cn=John)"]

    def test_extract_charset(self):
        args = self._parse([
            "-u", "http://x", "-d", "a=b", "-p", "a",
            "--extract-charset", "abc123",
        ])
        assert args.extract_charset == "abc123"
    def test_timeout_and_retry_options(self):
        args = self._parse([
            "-u", "http://x", "-d", "a=b", "-p", "a",
            "--timeout", "2.5",
            "--timeout-retries", "4",
            "--error-sleep-seconds", "3",
        ])
        assert args.timeout == 2.5
        assert args.timeout_retries == 4
        assert args.error_sleep_seconds == 3

    def test_can_disable_sleep_after_error(self):
        args = self._parse([
            "-u", "http://x", "-d", "a=b", "-p", "a",
            "--no-sleep-after-error",
        ])
        assert args.sleep_after_error is False

    def test_invalid_timeout_exits(self):
        try:
            self._parse(["-u", "http://x", "-d", "a=b", "-p", "a", "--timeout", "0"])
            assert False, "Expected SystemExit"
        except SystemExit:
            pass
