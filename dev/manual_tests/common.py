"""Private settings and credential-safe errors for manual connector tests."""
import os
import re
import stat


class SetupError(ValueError):
    """Fixed, credential-free setup messages safe to show in the terminal."""


def private_settings(path):
    fd = os.open(path.expanduser(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise SetupError("Token file must be a regular file owned by you with private permissions; use chmod 600 on it.")
        raw = file.read(16 * 1024 + 1)
    if len(raw) > 16 * 1024:
        raise SetupError("Token file exceeds the size limit.")
    values = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or key not in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "GRAFANA_URL", "GRAFANA_API_KEY") or key in values:
            raise SetupError("Private settings accept only Slack tokens, GRAFANA_URL and GRAFANA_API_KEY, without duplicate assignments.")
        if value[:1] in ("'", '"'):
            if len(value) < 2 or value[-1] != value[0]:
                raise SetupError("Token file has an unmatched quote.")
            value = value[1:-1]
        values[key] = value
    return values


def safe_error(error):
    response = getattr(error, "response", None)
    code = response.get("error") if response is not None else None
    return code if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,60}", code) else type(error).__name__
