"""Control-plane state: requests + audit log.
DATABASE_URL set -> PostgreSQL (psycopg); unset -> SQLite file at DB_PATH (local dev / tests)."""
import contextlib
import json
import os
import sqlite3
import threading
import time

_DDL = """CREATE TABLE IF NOT EXISTS requests(
  id {pk}, title TEXT, description TEXT, cloud TEXT, kind TEXT DEFAULT 'terraform',
  status TEXT, outputs TEXT DEFAULT '{{}}', created DOUBLE PRECISION);
CREATE TABLE IF NOT EXISTS audit(
  id {pk}, ts DOUBLE PRECISION, actor TEXT, event TEXT, detail TEXT);"""
_ready, _lock = set(), threading.Lock()


@contextlib.contextmanager
def _conn():
    url = os.getenv("DATABASE_URL")
    if url:
        import psycopg
        from psycopg.rows import dict_row

        c, pk = psycopg.connect(url, row_factory=dict_row), "BIGSERIAL PRIMARY KEY"
    else:
        url = os.getenv("DB_PATH", "devops.db")
        c, pk = sqlite3.connect(url), "INTEGER PRIMARY KEY"
        c.row_factory = sqlite3.Row
    try:
        with _lock:  # create tables once per process per database (also avoids concurrent-DDL races)
            if url not in _ready:
                for stmt in _DDL.format(pk=pk).split(";"):
                    if stmt.strip():
                        c.execute(stmt)
                c.commit()
                _ready.add(url)
        yield c
        c.commit()
    finally:
        c.close()


def _x(c, sql, args=()):
    """Run one statement; '?' placeholders work on both backends."""
    if os.getenv("DATABASE_URL"):
        sql = sql.replace("?", "%s")
    return c.execute(sql, args)


def _row(r):
    d = dict(r)
    d["outputs"] = json.loads(d["outputs"])
    return d


def create(title, description, cloud, kind="terraform"):
    with _conn() as c:
        return _x(
            c,
            "INSERT INTO requests(title,description,cloud,kind,status,created) VALUES(?,?,?,?,?,?) RETURNING id",
            (title, description, cloud, kind, "queued", time.time()),
        ).fetchone()["id"]


def get(rid):
    with _conn() as c:
        r = _x(c, "SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
    return _row(r) if r else None


def list_all():
    with _conn() as c:
        return [_row(r) for r in _x(c, "SELECT * FROM requests ORDER BY id DESC").fetchall()]


def update(rid, status=None, outputs=None):
    with _conn() as c:
        if status:
            _x(c, "UPDATE requests SET status=? WHERE id=?", (status, rid))
        if outputs is not None:
            _x(c, "UPDATE requests SET outputs=? WHERE id=?", (json.dumps(outputs), rid))


def claim(rid, from_status, to_status):
    """Atomic status transition; True only for the one caller that wins (prevents double-approve)."""
    with _conn() as c:
        return _x(c, "UPDATE requests SET status=? WHERE id=? AND status=?", (to_status, rid, from_status)).rowcount == 1


def audit(actor, event, detail=""):
    with _conn() as c:
        _x(c, "INSERT INTO audit(ts,actor,event,detail) VALUES(?,?,?,?)", (time.time(), actor, event, str(detail)[:2000]))


def audit_log(limit=100):
    with _conn() as c:
        return [dict(r) for r in _x(c, "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
