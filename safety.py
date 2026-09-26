"""Read-only SQL guardrails.

The whole point of this server is that an AI agent can *look* at production
data without being able to change it. The database account should live in a
read-only role as well, but this module is the second line of defence: a
whitelist parser that refuses anything that is not a single read statement.

Kept dependency-free and unit-tested (see tests/test_safety.py).
"""

from __future__ import annotations

import re

#: Statements an agent may run. Deliberately small.
ALLOWED_STARTS = ("select", "with", "show", "describe", "desc", "explain")

#: Forbidden as *whole words* anywhere in the statement (so a legit column like
#: `deleted` or `created_at` does not trip the guard).
FORBIDDEN_WORDS = (
    "insert",
    "update",
    "delete",
    "replace",
    "merge",
    "upsert",
    "drop",
    "alter",
    "create",
    "truncate",
    "rename",
    "grant",
    "revoke",
    "call",
    "commit",
    "rollback",
    "begin",
    "set",
    "lock",
    "outfile",
    "dumpfile",
    "load_file",
)

#: Forbidden as raw substrings (they contain punctuation or spaces).
FORBIDDEN_PHRASES = (
    "into outfile",
    "into dumpfile",
    "for update",
    "lock in share mode",
    "start transaction",
    "sleep(",
    "benchmark(",
)

_FORBIDDEN_WORD_RE = re.compile(
    r"\b(" + "|".join(FORBIDDEN_WORDS) + r")\b", re.IGNORECASE
)

_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_HASH_COMMENT_RE = re.compile(r"#[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def strip_comments(sql: str) -> str:
    """Remove SQL comments so they cannot hide a second statement."""
    sql = _BLOCK_COMMENT_RE.sub(" ", sql)
    sql = _LINE_COMMENT_RE.sub(" ", sql)
    sql = _HASH_COMMENT_RE.sub(" ", sql)
    return sql


def is_read_only_sql(sql: str) -> tuple[bool, str]:
    """Return ``(ok, reason)`` for a candidate statement.

    A statement is accepted only when it is a *single* statement that starts
    with one of :data:`ALLOWED_STARTS` and contains none of
    :data:`FORBIDDEN_WORDS` / :data:`FORBIDDEN_PHRASES`.
    """
    if not sql or not sql.strip():
        return False, "empty statement"

    cleaned = strip_comments(sql).strip()

    if ";" in cleaned.rstrip(";"):
        return False, "multiple statements are not allowed"
    cleaned = cleaned.rstrip(";").strip()
    if not cleaned:
        return False, "empty statement"

    lowered = cleaned.lower()
    if not lowered.startswith(ALLOWED_STARTS):
        return False, "only read-only statements are allowed (select/with/show/describe/explain)"

    padded = f" {lowered} "
    match = _FORBIDDEN_WORD_RE.search(cleaned)
    if match:
        return False, f"forbidden keyword: {match.group(1)}"
    for phrase in FORBIDDEN_PHRASES:
        if phrase in padded:
            return False, f"forbidden keyword: {phrase.strip()}"

    return True, "ok"


def clamp_rows(rows: list, max_rows: int) -> tuple[list, bool]:
    """Trim a result set to ``max_rows``; returns ``(rows, truncated)``."""
    if max_rows <= 0 or len(rows) <= max_rows:
        return rows, False
    return rows[:max_rows], True
