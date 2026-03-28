# ldapmap

`ldapmap` is a blind LDAP injection scanner and extractor.

It helps you:
- detect LDAP injection behavior in HTTP endpoints
- discover available LDAP attributes
- extract attribute values when injection is confirmed

## Installation

### From source (recommended for development)

```bash
pip install -e .
```

## Quick start

Form-data target:

```bash
ldapmap \
  --url http://target/login \
  --data "username=admin&password=INJECT_HERE" \
  --param password
```

JSON target:

```bash
ldapmap \
  --url http://target/login \
  --jsondata '{"username":"admin","password":"INJECT_HERE"}' \
  --param password
```

## Common options

- `--extract ATTRIBUTE` extract one LDAP attribute (for example `userPassword`)
- `--attributes ATTR` include additional attributes during discovery (repeatable)
- `--extract-filter FILTER` add extraction constraints (repeatable)
- `--find-all` continue searching for all matching values
- `--exclude-value VALUE` skip a known extracted value
- `--true-status CODE` / `--false-status CODE` classify HTTP status codes (repeatable)
- `--proxy URL` route HTTP traffic through a proxy
- `-v`, `--verbose` print every outgoing payload

Use `ldapmap -h` for the complete CLI reference.

## Development

Run tests from the repository root:

```bash
python -m pytest -q
```
