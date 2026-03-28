from unittest.mock import MagicMock

import ldapmap

from tests.helpers import make_response


class TestExtractAttribute:
    def test_extracts_known_value(self):
        target = "ab"
        session = MagicMock()

        def side_effect(url, data, timeout):
            from urllib.parse import unquote
            param_val = data.get("p", "")
            decoded = unquote(param_val)
            marker = "userPassword="
            if marker in decoded:
                after = decoded[decoded.index(marker) + len(marker):]
                if after.endswith("*)(userPassword="):
                    candidate = after[:-16]
                elif after.endswith("*)("):
                    candidate = after[:-3]
                elif after.endswith("*)"):
                    candidate = after[:-2]
                elif "*" in after:
                    candidate = after.rsplit("*", 1)[0]
                else:
                    candidate = after
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
            from urllib.parse import unquote
            decoded = unquote(data.get("p", ""))
            marker = "userPassword="
            if marker not in decoded:
                return make_response(200, b"y" * 999)

            # Only accept the second template: )(attr=<prefix>*)(attr=
            if "*)(userPassword=" not in decoded:
                return make_response(200, b"y" * 999)

            after = decoded[decoded.index(marker) + len(marker):]
            if after.endswith("*)(userPassword="):
                candidate = after[:-16]
            elif after.endswith("*)("):
                candidate = after[:-3]
            elif after.endswith("*)"):
                candidate = after[:-2]
            elif "*" in after:
                candidate = after.rsplit("*", 1)[0]
            else:
                candidate = after
            if target.startswith(candidate):
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
            from urllib.parse import unquote
            decoded = unquote(data.get("p", ""))
            marker = "userPassword="
            if marker in decoded:
                after = decoded[decoded.index(marker) + len(marker):]
                if after.endswith("*)(userPassword="):
                    candidate = after[:-16]
                elif after.endswith("*)("):
                    candidate = after[:-3]
                elif after.endswith("*)"):
                    candidate = after[:-2]
                elif "*" in after:
                    candidate = after.rsplit("*", 1)[0]
                else:
                    candidate = after
                if target.startswith(candidate):
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

    def test_find_all_extracts_multiple_values(self):
        values = {"admin", "john"}
        session = MagicMock()

        def side_effect(url, data, timeout):
            from urllib.parse import unquote
            decoded = unquote(data.get("p", ""))
            marker = "uid="
            if marker not in decoded:
                return make_response(200, b"y" * 999)
            after = decoded[decoded.index(marker) + len(marker):]
            if after.endswith("*)(uid="):
                candidate = after[:-6]
            elif after.endswith("*)("):
                candidate = after[:-3]
            elif after.endswith("*)"):
                candidate = after[:-2]
            elif after.endswith(")("):
                candidate = after[:-2]
            else:
                candidate = after

            if "*" in after:
                if any(v.startswith(candidate) for v in values):
                    return make_response(200, b"x" * 100)
            else:
                if candidate in values:
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
            from urllib.parse import unquote
            decoded = unquote(data.get("p", ""))
            marker = "uid="
            if marker not in decoded:
                return make_response(200, b"y" * 999)
            after = decoded[decoded.index(marker) + len(marker):]
            if after.endswith("*)(uid="):
                candidate = after[:-6]
            elif after.endswith("*)("):
                candidate = after[:-3]
            elif after.endswith("*)"):
                candidate = after[:-2]
            elif after.endswith(")("):
                candidate = after[:-2]
            else:
                candidate = after

            cache_key = ("*" in after, candidate)
            seen[cache_key] = seen.get(cache_key, 0) + 1

            if "*" in after:
                if any(v.startswith(candidate) for v in values):
                    return make_response(200, b"x" * 100)
            else:
                if candidate in values:
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
        # Prefix checks are cached; each distinct prefix is requested once.
        assert seen[(True, "a")] == 1

    def test_extract_with_manual_filter_constraints(self):
        target = "123"
        session = MagicMock()

        def side_effect(url, data, timeout):
            from urllib.parse import unquote

            decoded = unquote(data.get("p", ""))
            if "(uid=admin)" not in decoded:
                return make_response(200, b"y" * 999)
            marker = "telephoneNumber="
            if marker not in decoded:
                return make_response(200, b"y" * 999)
            after = decoded[decoded.index(marker) + len(marker):]
            if after.endswith("*)(telephoneNumber="):
                candidate = after[:-18]
            elif after.endswith("*)("):
                candidate = after[:-3]
            elif after.endswith("*)"):
                candidate = after[:-2]
            elif "*" in after:
                candidate = after.rsplit("*", 1)[0]
            else:
                candidate = after
            if target.startswith(candidate):
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
            from urllib.parse import unquote

            decoded = unquote(data.get("p", ""))
            marker = "uid="
            if marker not in decoded:
                return make_response(200, b"y" * 999)
            after = decoded[decoded.index(marker) + len(marker):]
            if after.endswith("*)(uid="):
                candidate = after[:-6]
            elif after.endswith("*)("):
                candidate = after[:-3]
            elif after.endswith("*)"):
                candidate = after[:-2]
            elif "*" in after:
                candidate = after.rsplit("*", 1)[0]
            else:
                candidate = after

            if "*" in after and candidate in {"", "3"}:
                return make_response(200, b"x" * 100)
            if "*" not in after and candidate == "3":
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

    def test_find_all_reports_first_char_hits_and_uses_depth_first_search(self, capsys):
        values = {"aa", "bz"}
        session = MagicMock()
        wildcard_candidates = []

        def side_effect(url, data, timeout):
            from urllib.parse import unquote

            decoded = unquote(data.get("p", ""))
            marker = "uid="
            if marker not in decoded:
                return make_response(200, b"y" * 999)
            after = decoded[decoded.index(marker) + len(marker):]
            if after.endswith("*)(uid="):
                candidate = after[:-6]
            elif after.endswith("*)("):
                candidate = after[:-3]
            elif after.endswith("*)"):
                candidate = after[:-2]
            elif "*" in after:
                candidate = after.rsplit("*", 1)[0]
            else:
                candidate = after

            if "*" in after:
                wildcard_candidates.append(candidate)
                if any(v.startswith(candidate) for v in values):
                    return make_response(200, b"x" * 100)
            else:
                if candidate in values:
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
        # First character checks should test the entire charset before deeper probes.
        assert wildcard_candidates[1:4] == ["a", "b", "z"]
        # Then continue depth-first on 'a' before traversing into 'b'.
        assert wildcard_candidates.index("aa") < wildcard_candidates.index("ba")
