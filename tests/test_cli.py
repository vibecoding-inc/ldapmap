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
