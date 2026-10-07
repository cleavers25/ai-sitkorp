import re
from typing import Any

REDACTED = "***REDACTED***"
_SENSITIVE_KEY = re.compile(
    r"pass(word|phrase)?|secret|token|private_?key|api_?key|authorization|cookie", re.I
)
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S
)
# KEY=value / KEY: value where the key name looks secret (e.g. lines of an exposed .env file).
_SECRET_ASSIGNMENT = re.compile(
    r"(?im)\b([A-Z0-9_.-]*(?:PASS(?:WORD)?|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_.-]*)"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}")
_API_KEY_LIKE = re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})")


def redact_text(text: str) -> str:
    """Mask secret-looking values inside free text (server output, web content, evidence)."""
    text = _PEM_BLOCK.sub(REDACTED, text)
    text = _SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    return _API_KEY_LIKE.sub(REDACTED, text)


def redact(value: Any) -> Any:
    """Recursively strip secrets from data before it is logged, stored as evidence, or sent to an LLM."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if isinstance(k, str) and _SENSITIVE_KEY.search(k) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
