from __future__ import annotations

import re
from urllib.parse import unquote

SECRET_PATTERNS = [
    ("aws-access-id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]
SENSITIVE_NAME = r"(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|private[_-]?key|secret(?:[_-]?key)?|password|token|authorization|client[_-]?secret|database[_-]?url)"
ASSIGNMENT = re.compile(r'''(?i)((?:["']?)\b''' + SENSITIVE_NAME + r'''(?:["']?)\s*[:=]\s*["']?)([^\s"'<>;,}\]]+)''')
QUERY_SECRET = re.compile(r"(?i)([?&](?:token|key|api_key|secret|password|auth)=)[^&#\s]+")
QUERY_VALUE = re.compile(r"([?&])([^&#=\s]+)=([^&#\s]*)")
URL_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s?#]*@")
PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN ((?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----.*?(?:-----END \1-----|$)", re.S)
AUTH_VALUE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*")


def redact(text: str) -> str:
    # Remove the complete PEM block, including truncated keys; masking only its
    # header leaves recoverable key material in exports. Also handles JSON \n escapes.
    text = PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", text)
    text = AUTH_VALUE.sub(lambda m: m[1] + " [REDACTED]", text)
    text = URL_USERINFO.sub(lambda m: m[1] + "[REDACTED]@", text)
    for _, pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = ASSIGNMENT.sub(lambda m: m[1] + "[REDACTED]", text)
    text = QUERY_SECRET.sub(lambda m: m[1] + "[REDACTED]", text)
    return QUERY_VALUE.sub(lambda m: m[1] + m[2] + "=[REDACTED]" if unquote(m[2]).lower() in {"token", "key", "api_key", "apikey", "secret", "password", "auth", "access_token"} else m[0], text)


def redact_data(value: object) -> object:
    if isinstance(value, dict):
        return {redact(str(k)): ("[REDACTED]" if re.fullmatch(SENSITIVE_NAME, str(k), re.I) or str(k).lower() in {"cookie", "set-cookie", "match"} else redact_data(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_data(v) for v in value]
    if isinstance(value, str):
        return redact(value)
    return value
