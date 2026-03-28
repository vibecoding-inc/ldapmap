# ldapmap

## HTTP status classification

You can explicitly define which HTTP status codes should be treated as `TRUE`
and `FALSE` during blind response classification:

- `--true-status <code>` (repeatable)
- `--false-status <code>` (repeatable)

Any status code not included in either set is treated as an `ERROR` (unknown),
not as `FALSE`.

Verbose mode (`-v` / `--verbose`) also logs the HTTP status code for each
request.
