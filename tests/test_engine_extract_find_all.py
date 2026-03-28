from unittest.mock import MagicMock
from urllib.parse import unquote

import ldapmap

from tests.helpers import extract_candidate_from_data, make_response


class TestExtractAttributeFindAll:
    def test_find_all_extracts_multiple_values(self):
        values = {"admin", "john"}
        session = MagicMock()

        def side_effect(url, data, timeout):
            decoded = unquote(data.get("p", ""))
            candidate = extract_candidate_from_data(data, "uid=")
            if candidate is None:
                return make_response(200, b"y" * 999)

            if "*" in decoded:
                if any(value.startswith(candidate) for value in values):
                    return make_response(200, b"x" * 100)
            elif candidate in values:
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
            find_all=True,
        )
        assert sorted(result) == ["admin", "john"]

    def test_query_cache_reuses_prefix_checks(self):
        values = {"ab", "ac"}
        session = MagicMock()
        seen = {}

        def side_effect(url, data, timeout):
            decoded = unquote(data.get("p", ""))
            candidate = extract_candidate_from_data(data, "uid=")
            if candidate is None:
                return make_response(200, b"y" * 999)

            cache_key = ("*" in decoded, candidate)
            seen[cache_key] = seen.get(cache_key, 0) + 1

            if "*" in decoded:
                if any(value.startswith(candidate) for value in values):
                    return make_response(200, b"x" * 100)
            elif candidate in values:
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
            find_all=True,
        )

        assert sorted(result) == ["ab", "ac"]
        assert seen[(True, "a")] == 1

    def test_find_all_reports_first_char_hits_and_uses_depth_first_search(self, capsys):
        values = {"aa", "bz"}
        session = MagicMock()
        wildcard_candidates = []

        def side_effect(url, data, timeout):
            decoded = unquote(data.get("p", ""))
            candidate = extract_candidate_from_data(data, "uid=")
            if candidate is None:
                return make_response(200, b"y" * 999)

            if "*" in decoded:
                wildcard_candidates.append(candidate)
                if any(value.startswith(candidate) for value in values):
                    return make_response(200, b"x" * 100)
            elif candidate in values:
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
            find_all=True,
            charset="abz",
        )

        assert sorted(result) == ["aa", "bz"]
        output = capsys.readouterr().out
        assert "First-character hits: at least 2" in output
        assert wildcard_candidates[0] == ""
        assert wildcard_candidates[1:4] == ["a", "b", "z"]
        assert wildcard_candidates.index("aa") < wildcard_candidates.index("ba")
