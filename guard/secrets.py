"""Deterministic secret detection by known formats and credential-shaped context.

What is detected:
  1. Known token formats (AWS, GitHub, Slack, Stripe, Google, Anthropic, OpenAI-style,
     JWT, PEM private keys, Hugging Face, npm, GitLab, SendGrid, Telegram bot tokens).
  2. Credentials inside URLs: the password in user:pass@host userinfo, with a
     database-specific rule for connection strings (postgres://, mysql://, mongodb+srv://,
     redis://, ... and key=value strings such as "Server=...;Password=...").
  3. Bearer tokens after the word "bearer".
  4. Values assigned to credential-named keys (KEY=..., "key": "...", key: ...).

About entropy: there is NO standalone high-entropy detector. A random-looking string
with no known prefix and no credential-named key is not flagged. Shannon entropy is
used only as a gate in rule 4: a value assigned to a credential-like name is flagged
only if its entropy is at least (entropy_threshold - 0.5) or it contains a digit, so
"token=counter" is not flagged. This is deliberate: a global entropy detector produces
too many false positives on hashes, UUIDs, base64 data and minified code.

Not re-flagged: Hermes's own redaction sentinels («redacted:AKIA…», «redacted-secret»,
«redacted-vault-secret»), which Hermes writes into read_file output in place of the key.
"""
import bisect
import math
import re
from typing import List

from .findings import Finding, mask

# (rule name, compiled regex, severity)
_PATTERNS = [
    ("secret.aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("secret.github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "high"),
    ("secret.github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "high"),
    ("secret.slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("secret.stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"), "high"),
    ("secret.google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("secret.anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "high"),
    ("secret.openai_style_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), "high"),
    ("secret.jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "high"),
    ("secret.private_key_block", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "high"),
    ("secret.huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "high"),
    ("secret.npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"), "high"),
    ("secret.gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])"), "high"),
    ("secret.sendgrid_key", re.compile(
        r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}(?![A-Za-z0-9_\-])"), "high"),
    ("secret.telegram_bot_token", re.compile(
        r"(?<![A-Za-z0-9_])\d{8,10}:AA[A-Za-z0-9_\-]{33}(?![A-Za-z0-9_\-])"), "high"),
]

# Every repeat next to a literal is bounded ({0,64}, {0,256}, ...): unbounded ones made some
# 1 MB inputs take minutes (quadratic backtracking), past Hermes's 30 s hook limit.

# scheme://user:password@host  -> the password group is redacted, the rest is kept.
_DB_SCHEMES = (r"(?:jdbc:)?(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|rediss|amqps?|mssql|"
               r"sqlserver|oracle|cockroachdb|clickhouse|db2)(?:\+[a-z0-9]+)?")  # +srv, +psycopg2
_URL_USERINFO = re.compile(
    r"(?i)\b([a-z][a-z0-9+.\-:]{0,31})://([^\s:/@?#'\"<>]{0,256}):([^\s:/@?#'\"<>]{1,256})@"
    r"(?=[A-Za-z0-9\[._\-])")
# A password containing ':' is excluded above: it is almost always another syntax
# (e.g. CVS "cvs://:pserver:anoncvs@host"), and real ones are percent-encoded.
_TEMPLATE = re.compile(r"^\{[^{}]*\}$|^%\(?\w*\)?s$")   # f"{password}", "%s", "%(pw)s"
_DB_SCHEME_RX = re.compile(rf"(?i)^(?:{_DB_SCHEMES})$")
# ADO.NET / ODBC style: Server=db;User Id=app;Password=...;  (needs a server/host key nearby)
_KV_CONNSTR = re.compile(
    r"(?i)(?:server|data source|host|hostname|address|addr)\s*=[^;\n]{1,256};[^\n]{0,1024}?"
    r"\b(?:password|pwd)\s*=\s*([^;'\"\s]+)")

# Authorization: Bearer xxxxx  (keep the scheme, mask the token)
_BEARER = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._\-~+/]{16,}=*)")

# KEY=value / "key": "value" where the key name suggests a credential
_ASSIGN = re.compile(
    r"""(?ix)
    \b([A-Za-z0-9_.\-]{0,64}(?:secret|token|passw(?:or)?d|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key)[A-Za-z0-9_.\-]{0,64})
    (\s*["']?\s*[:=]\s*["']?)
    ([^\s"'<>,;]{8,})
    """
)

# Hermes's own redaction sentinels (agent/redact.py, v0.22.2): «redacted:<prefix>…»,
# «redacted-secret», «redacted-vault-secret». Already masked, so never re-flag them.
# The label is Hermes's vendor prefix (at most 11 chars there); capping it at 16 means
# a full credential wrapped in guillemets (AKIA + 16 = 20 chars) is still detected.
_HERMES_SENTINEL = re.compile(r"«redacted(?::[A-Za-z0-9_.\-]{1,16}…|-secret|-vault-secret)»")

_PLACEHOLDER_WORDS = {
    "changeme", "password", "example", "your_api_key", "your-api-key",
    "xxxxxxxx", "placeholder", "redacted", "<redacted>", "none", "null",
}


class _Spans:
    """Sorted, non-overlapping [start, end) spans with O(log n) overlap checks."""

    def __init__(self, spans=()):
        self._starts, self._ends = [], []
        for s, e in spans:
            self.append((s, e))

    def overlaps(self, a: int, b: int) -> bool:
        i = bisect.bisect_left(self._starts, b)     # spans starting before b: indices < i
        return i > 0 and self._ends[i - 1] > a

    def append(self, span) -> None:
        s, e = span
        i = bisect.bisect_left(self._starts, s)
        self._starts.insert(i, s)
        self._ends.insert(i, e)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    v = value.lower().strip("\"'")
    if v in _PLACEHOLDER_WORDS:
        return True
    if v.startswith(("$", "${", "{{", "<", "%")):   # env refs / templates
        return True
    if len(set(v)) <= 3:                              # xxxxxxxx, 00000000
        return True
    return False


def find_secrets(text: str, entropy_threshold: float = 3.5) -> List[Finding]:
    """Return findings for known formats, URL/DB credentials, bearer tokens and
    credential-named assignments. entropy_threshold only gates the assignment rule
    (see module docstring); it never flags a bare string on its own."""
    findings: List[Finding] = []
    # Spans already claimed by a more specific rule (Hermes sentinels are pre-claimed).
    # Kept sorted and non-overlapping so a lookup is O(log n), not a scan of every span.
    covered = _Spans((m.start(), m.end()) for m in _HERMES_SENTINEL.finditer(text))
    overlaps = covered.overlaps

    for rule, rx, sev in _PATTERNS:
        for m in rx.finditer(text):
            if overlaps(m.start(), m.end()):
                continue
            covered.append((m.start(), m.end()))
            findings.append(Finding(
                rule=rule, reason=f"Matches the format of a credential ({rule.split('.')[1]}).",
                start=m.start(), end=m.end(), masked=mask(m.group(0)),
                severity=sev, replacement=f"[REDACTED:{rule.split('.')[1]}]"))

    for m in _URL_USERINFO.finditer(text):
        s, e = m.start(3), m.end(3)
        value = m.group(3)
        if overlaps(s, e) or _looks_like_placeholder(value) or set(value) <= {"*"} \
                or _TEMPLATE.match(value):
            continue
        is_db = bool(_DB_SCHEME_RX.match(m.group(1)))
        name = "db_connection_string" if is_db else "url_password"
        covered.append((s, e))
        findings.append(Finding(
            rule=f"secret.{name}",
            reason=("Password in a database connection string." if is_db
                    else "Password embedded in a URL (user:password@host)."),
            start=s, end=e, masked=mask(value), severity="high",
            replacement=f"[REDACTED:{name}]"))

    for m in _KV_CONNSTR.finditer(text):
        s, e = m.start(1), m.end(1)
        value = m.group(1)
        if overlaps(s, e) or _looks_like_placeholder(value) or _TEMPLATE.match(value):
            continue
        covered.append((s, e))
        findings.append(Finding(
            rule="secret.db_connection_string", reason="Password in a database connection string.",
            start=s, end=e, masked=mask(value), severity="high",
            replacement="[REDACTED:db_connection_string]"))

    for m in _BEARER.finditer(text):
        s, e = m.start(2), m.end(2)
        if overlaps(s, e):
            continue
        covered.append((s, e))
        findings.append(Finding(
            rule="secret.bearer_token", reason="Authorization bearer token.",
            start=s, end=e, masked=mask(m.group(2)), severity="high",
            replacement="[REDACTED:bearer_token]"))

    for m in _ASSIGN.finditer(text):
        s, e = m.start(3), m.end(3)
        value = m.group(3)
        if overlaps(s, e) or _looks_like_placeholder(value):
            continue
        # Credential-named key: require some randomness so "token=counter" isn't flagged
        if shannon_entropy(value) < entropy_threshold - 0.5 and not re.search(r"\d", value):
            continue
        covered.append((s, e))
        findings.append(Finding(
            rule="secret.assigned_credential",
            reason=f"Value assigned to credential-like name '{m.group(1)}'.",
            start=s, end=e, masked=mask(value), severity="high",
            replacement="[REDACTED:credential]"))

    return sorted(findings, key=lambda f: f.start)
