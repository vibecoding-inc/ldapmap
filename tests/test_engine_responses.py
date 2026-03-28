import ldapmap

from tests.helpers import make_response


class TestIsTrueResponse:
    def test_none_response_is_false(self):
        assert ldapmap.is_true_response(None, 200, 500) is False

    def test_matching_response_is_true(self):
        resp = make_response(200, b"x" * 500)
        assert ldapmap.is_true_response(resp, 200, 500) is True

    def test_within_tolerance_is_true(self):
        resp = make_response(200, b"x" * (500 + ldapmap.LENGTH_TOLERANCE))
        assert ldapmap.is_true_response(resp, 200, 500) is True

    def test_outside_tolerance_is_false(self):
        resp = make_response(200, b"x" * (500 + ldapmap.LENGTH_TOLERANCE + 1))
        assert ldapmap.is_true_response(resp, 200, 500) is False

    def test_wrong_status_is_false(self):
        resp = make_response(302, b"x" * 500)
        assert ldapmap.is_true_response(resp, 200, 500) is False

    def test_true_statuses_set_supported(self):
        resp = make_response(202, b"x" * 500)
        assert ldapmap.is_true_response(resp, {200, 202}, 500) is True


class TestClassifyResponse:
    def test_unknown_status_is_error(self):
        resp = make_response(418, b"teapot")
        assert ldapmap.classify_response(resp, {200}, 100, {401, 403}) == "error"

    def test_false_status_is_false(self):
        resp = make_response(401, b"denied")
        assert ldapmap.classify_response(resp, {200}, 100, {401, 403}) == "false"

    def test_true_status_with_matching_length_is_true(self):
        resp = make_response(200, b"x" * 100)
        assert ldapmap.classify_response(resp, {200}, 100, {401}) == "true"
