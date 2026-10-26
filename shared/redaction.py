"""Remove common credential values from persisted analysis text."""

import re
from pathlib import Path


_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL | re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    r"\b(password|passwd|secret|api[_ -]?key|access[_ -]?token|private[_ -]?key)"
    r"(\s*(?:=|:|\bis\b)\s*[\"']?)([^\s\"'<>,;]+)", re.IGNORECASE,
)
_URL_CREDENTIAL = re.compile(r"(https?://[^\s:/@]+:)[^\s@/]+(@)", re.IGNORECASE)


def collect_secret_values(paths: list[str]) -> tuple[str, ...]:
    """Collect common local credential values without persisting them."""
    values = set()
    for name in paths:
        if not isinstance(name, str) or not name:
            continue
        try:
            with Path(name).open("rb") as stream:
                content = stream.read(1024 * 1024).decode("utf-8", errors="ignore")
        except OSError:
            continue
        for match in _ASSIGNMENT.finditer(content):
            candidate = match.group(3).strip("'\";,")
            if len(candidate) >= 4:
                values.add(candidate)
        for block in _PRIVATE_KEY.finditer(content):
            values.add(block.group())
            for line in block.group().splitlines():
                if len(line) >= 16 and not line.startswith("-----"):
                    values.add(line.strip())
    return tuple(sorted(values, key=len, reverse=True))


def redact_text(value: str, secrets: tuple[str, ...] = ()) -> str:
    for secret in secrets:
        value = value.replace(secret, "[REDACTED]")
    value = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)
    value = _ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + "[REDACTED]", value)
    return _URL_CREDENTIAL.sub(r"\1[REDACTED]\2", value)


def redact_record(value, secrets: tuple[str, ...] = ()):
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, list):
        return [redact_record(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: redact_record(item, secrets) for key, item in value.items()}
    return value
