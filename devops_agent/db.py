"""Control-plane state: requests + audit log. SQLite (ponytail: swap for Postgres if multi-replica)."""
import contextlib
import json
import os
import sqlite3
import time


@contextlib.contextmanager
def _conn():
    c = sqlite3.connect(os.getenv("DB_PATH", "devops.db"))
    c.row_factory = sqlite3.Row
    c.executescript(
        """CREATE TABLE IF NOT EXISTS requests(
             id INTEGER PRIMARY KEY, title TEXT, description TEXT, cloud TEXT, kind TEXT DEFAULT 'terraform',
             status TEXT, outputs TEXT DEFAULT '{}', created REAL);
           CREATE TABLE IF NOT EXISTS audit(
             id INTEGER PRIMARY KEY, ts REAL, actor TEXT, event TEXT, detail TEXT);"""
    )
    try:
        yield c
        c.commit()
    finally:
        c.close()


def _row(r):
    d = dict(r)
    d["outputs"] = json.loads(d["outputs"])
    return d


def create(title, description, cloud, kind="terraform"):
    with _conn() as c:
        return c.execute(
            "INSERT INTO requests(title,description,cloud,kind,status,created) VALUES(?,?,?,?,?,?)",
            (title, description, cloud, kind, "queued", time.time()),
        ).lastrowid


def get(rid):
    with _conn() as c:
        r = c.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
    return _row(r) if r else None


def list_all():
    with _conn() as c:
        return [_row(r) for r in c.execute("SELECT * FROM requests ORDER BY id DESC")]


def update(rid, status=None, outputs=None):
    with _conn() as c:
        if status:
            c.execute("UPDATE requests SET status=? WHERE id=?", (status, rid))
        if outputs is not None:
            c.execute("UPDATE requests SET outputs=? WHERE id=?", (json.dumps(outputs), rid))


def audit(actor, event, detail=""):
    with _conn() as c:
        c.execute(
            "INSERT INTO audit(ts,actor,event,detail) VALUES(?,?,?,?)",
            (time.time(), actor, event, str(detail)[:2000]),
        )


def audit_log(limit=100):
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]
