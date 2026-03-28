from unittest.mock import patch

import ldapmap


class TestMain:
    @patch("ldapmap.build_session")
    def test_main_missing_param_exits(self, mock_build_session):
        with patch("sys.argv", ["ldapmap", "-u", "http://x", "-d", "a=b", "-p", "z"]):
            try:
                ldapmap.main()
                assert False, "Expected SystemExit"
            except SystemExit:
                pass

    @patch("ldapmap.extract_attribute", return_value="secret")
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_extract_path(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_extract
    ):
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
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "-d", "user=admin&pass=x", "-p", "pass"
        ]):
            ldapmap.main()
        mock_discover.assert_called_once()

    @patch("ldapmap.build_session")
    def test_main_invalid_json_exits(self, mock_build_session):
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "--jsondata", "not-valid-json", "-p", "pass"
        ]):
            try:
                ldapmap.main()
                assert False, "Expected SystemExit"
            except SystemExit:
                pass

    @patch("ldapmap.build_session")
    def test_main_jsondata_non_object_exits(self, mock_build_session):
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "--jsondata", '["a","b"]', "-p", "a"
        ]):
            try:
                ldapmap.main()
                assert False, "Expected SystemExit"
            except SystemExit:
                pass

    @patch("ldapmap.build_session")
    def test_main_missing_param_in_jsondata_exits(self, mock_build_session):
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x",
            "--jsondata", '{"username":"","email":""}', "-p", "password"
        ]):
            try:
                ldapmap.main()
                assert False, "Expected SystemExit"
            except SystemExit:
                pass

    @patch("ldapmap.discover_attributes", return_value=["uid"])
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_jsondata_discovery_path(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_discover
    ):
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x",
            "--jsondata", '{"username":"","email":"INJECT_HERE"}',
            "-p", "email",
        ]):
            ldapmap.main()
        mock_discover.assert_called_once()
        args_positional = mock_discover.call_args[0]
        assert args_positional[7] is True

    @patch("ldapmap.extract_attribute", return_value="user@example.com")
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_jsondata_extract_path(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_extract
    ):
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x",
            "--jsondata", '{"username":"","email":"INJECT_HERE"}',
            "-p", "email", "--extract", "mail",
        ]):
            ldapmap.main()
        mock_extract.assert_called_once()
        args_positional = mock_extract.call_args[0]
        assert args_positional[8] is True

    @patch("ldapmap.discover_attributes", return_value=["uid"])
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_attributes_forwarded_to_discover(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_discover
    ):
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "-d", "user=admin&pass=x",
            "-p", "pass", "--attributes", "uid", "--attributes", "cn",
        ]):
            ldapmap.main()

        mock_discover.assert_called_once()
        call_args = mock_discover.call_args[0]
        attr_list = call_args[8]
        assert "uid" in attr_list
        assert "cn" in attr_list
        assert attr_list.index("uid") < attr_list.index("mail")

        detect_call_args = mock_detect.call_args[0]
        assert detect_call_args[8] == "uid"

    @patch("ldapmap.discover_attributes", return_value=[])
    @patch("ldapmap.detect_injection", return_value=False)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_no_attributes_uses_objectclass_probe(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_discover
    ):
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "-d", "user=admin&pass=x", "-p", "pass",
        ]):
            ldapmap.main()

        detect_call_args = mock_detect.call_args[0]
        assert detect_call_args[8] == "objectClass"

    @patch("ldapmap.discover_attributes", return_value=[])
    @patch("ldapmap.detect_injection", return_value=False)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_forwards_true_false_status_sets(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_discover
    ):
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "-d", "user=admin&pass=x", "-p", "pass",
            "--true-status", "200", "--true-status", "302",
            "--false-status", "401", "--false-status", "403",
        ]):
            ldapmap.main()

        assert mock_detect.call_args.kwargs["true_statuses"] == {200, 302}
        assert mock_detect.call_args.kwargs["false_statuses"] == {401, 403}

    @patch("ldapmap.extract_attribute", return_value="secret")
    @patch("ldapmap.detect_injection", return_value=True)
    @patch("ldapmap.calibrate", return_value=(200, 100))
    @patch("ldapmap.get_baseline", return_value=(200, 100))
    @patch("ldapmap.build_session")
    def test_main_forwards_extract_search_options(
        self, mock_session, mock_baseline, mock_calibrate,
        mock_detect, mock_extract
    ):
        with patch("sys.argv", [
            "ldapmap", "-u", "http://x", "-d", "user=admin&pass=x",
            "-p", "pass", "--extract", "uid",
            "--exclude-value", "admin", "--find-all",
        ]):
            ldapmap.main()

        kwargs = mock_extract.call_args.kwargs
        assert kwargs["exclude_value"] == "admin"
        assert kwargs["find_all"] is True
