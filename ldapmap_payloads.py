from urllib.parse import quote


def build_payload_data(
    base_data: dict,
    param: str,
    injection: str,
    use_json: bool = False,
) -> dict:
    """
    Return a copy of *base_data* with *param* replaced by *injection*.

    For form data (``use_json=False``) the injection string is URL-encoded
    before substitution so that special LDAP characters travel correctly over
    HTTP.  For JSON data (``use_json=True``) the raw string is used because
    the requests library serialises the dict to JSON automatically.
    """
    payload_data = dict(base_data)
    if use_json:
        payload_data[param] = injection
    else:
        # quote() encodes characters that would break the form field; the server
        # decodes them back before passing the value to the LDAP query.
        payload_data[param] = quote(injection, safe="")
    return payload_data
