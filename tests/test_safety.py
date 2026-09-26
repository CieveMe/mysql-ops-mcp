"""Unit tests for the read-only guardrail - run with `pytest -q`."""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from safety import clamp_rows, is_read_only_sql, strip_comments  # noqa: E402


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "select id, name from orders limit 10",
        "  SELECT COUNT(*) FROM orders WHERE status = 1  ",
        "WITH t AS (SELECT 1) SELECT * FROM t",
        "SHOW TABLES",
        "DESCRIBE orders",
        "EXPLAIN SELECT 1",
        "SELECT * FROM orders;",
    ],
)
def test_accepts_read_only(sql):
    ok, reason = is_read_only_sql(sql)
    assert ok, reason


@pytest.mark.parametrize(
    "sql",
    [
        "",
        "   ",
        "UPDATE orders SET status = 0",
        "DELETE FROM orders",
        "DROP TABLE orders",
        "TRUNCATE orders",
        "INSERT INTO orders VALUES (1)",
        "SELECT 1; DROP TABLE orders",
        "SELECT * FROM orders INTO OUTFILE '/tmp/x'",
        "SELECT SLEEP(10)",
        "SET GLOBAL max_connections = 1",
        "CREATE TABLE t (id int)",
    ],
)
def test_rejects_writes_and_smuggling(sql):
    ok, _ = is_read_only_sql(sql)
    assert not ok


def test_comment_cannot_hide_second_statement():
    ok, _ = is_read_only_sql("SELECT 1 /* ; DROP TABLE orders */")
    assert ok  # single read statement, the payload lives inside a comment

    ok, reason = is_read_only_sql("SELECT 1 -- \n; DROP TABLE orders")
    assert not ok
    assert "multiple" in reason or "forbidden" in reason


def test_delete_as_column_name_still_rejected_by_keyword_scan():
    # `deleted` is a legit column in the example schema; the guard looks for the
    # keyword as a whole word, so this must still pass.
    ok, _ = is_read_only_sql("SELECT * FROM orders WHERE deleted = 0")
    assert ok


def test_strip_comments():
    assert "drop" not in strip_comments("SELECT 1 -- drop\n")
    assert strip_comments("SELECT /* drop */ 1").strip() == "SELECT   1"


def test_clamp_rows():
    rows = list(range(10))
    kept, truncated = clamp_rows(rows, 4)
    assert kept == [0, 1, 2, 3]
    assert truncated is True

    kept, truncated = clamp_rows(rows, 50)
    assert kept == rows
    assert truncated is False
