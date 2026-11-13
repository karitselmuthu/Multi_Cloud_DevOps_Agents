"""Control-plane state: requests, plans, approval tokens, audit log.
DATABASE_URL set -> PostgreSQL (psycopg); unset -> SQLite file at DB_PATH (local dev / tests).
Schema changes are versioned migrations (append only) so existing databases upgrade in place."""
import contextlib
import json
import os
import sqlite3
import threading
import time

_MIGRATIONS = [
    [  # v1
        "CREATE TABLE IF NOT EXISTS requests(id {pk}, title TEXT, description TEXT, cloud TEXT, kind TEXT DEFAULT 'terraform',"
        " status TEXT, outputs TEXT DEFAULT '{}', created DOUBLE PRECISION)",
        "CREATE TABLE IF NOT EXISTS audit(id {pk}, ts DOUBLE PRECISION, actor TEXT, event TEXT, detail TEXT)",
    ],
    [  # v2: identity, plan binding, single-use approval tokens, audit attribution
        "ALTER TABLE requests ADD COLUMN requester TEXT DEFAULT ''",
        "ALTER TABLE audit ADD COLUMN request_id BIGINT",
        "ALTER TABLE audit ADD COLUMN plan_hash TEXT",
        "CREATE TABLE IF NOT EXISTS plans(request_id BIGINT PRIMARY KEY, plan_hash TEXT, blob TEXT, summary TEXT)",
        "CREATE TABLE IF NOT EXISTS approval_tokens(jti TEXT PRIMARY KEY, request_id BIGINT, approver TEXT, used_at DOUBLE PRECISION)",
    ],
]
_ready, _lock = set(), threading.Lock()


def _migrate(c, pg):
    pk = "BIGSERIAL PRIMARY KEY" if pg else "INTEGER PRIMARY KEY"
    if pg:
        c.execute("SELECT pg_advisory_lock(7342)")  # serialise across processes (api + workers start together)
    c.execute("CREATE TABLE IF NOT EXISTS schema_version(v INTEGER)")
    cur = c.execute("SELECT max(v) AS v FROM schema_version").fetchone()["v"] or 0
    for v, stmts in enumerate(_MIGRATIONS, 1):
        if v > cur:
            for s in stmts:
                c.execute(s.replace("{pk}", pk))
            c.execute(f"INSERT INTO schema_version VALUES({v})")
    c.commit()
    if pg:
        c.execute("SELECT pg_advisory_unlock(7342)")


@contextlib.contextmanager
def _conn():
    url = os.getenv("DATABASE_URL")
    if url:
        import psycopg
        from psycopg.rows import dict_row

        c = psycopg.connect(url, row_factory=dict_row)
    else:
        url = os.getenv("DB_PATH", "devops.db")
        c = sqlite3.connect(url)
        c.row_factory = sqlite3.Row
    try:
        with _lock:
            if url not in _ready:
                _migrate(c, bool(os.getenv("DATABASE_URL")))
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


def create(title, description, cloud, kind="terraform", requester=""):
    with _conn() as c:
        return _x(
            c,
            "INSERT INTO requests(title,description,cloud,kind,requester,status,created) VALUES(?,?,?,?,?,?,?) RETURNING id",
            (title, description, cloud, kind, requester, "queued", time.time()),
        ).fetchone()["id"]


def get(rid):
    with _conn() as c:
        r = _x(c, "SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
    return _row(r) if r else None


def list_all(requester=None):
    with _conn() as c:
        if requester is None:
            rows = _x(c, "SELECT * FROM requests ORDER BY id DESC").fetchall()
        else:
            rows = _x(c, "SELECT * FROM requests WHERE requester=? ORDER BY id DESC", (requester,)).fetchall()
    return [_row(r) for r in rows]


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


def set_plan(rid, plan_hash, blob_b64, summary):
    with _conn() as c:
        _x(
            c,
            "INSERT INTO plans(request_id,plan_hash,blob,summary) VALUES(?,?,?,?) ON CONFLICT(request_id) DO UPDATE SET "
            "plan_hash=excluded.plan_hash, blob=excluded.blob, summary=excluded.summary",
            (rid, plan_hash, blob_b64, summary),
        )


def get_plan(rid):
    with _conn() as c:
        r = _x(c, "SELECT * FROM plans WHERE request_id=?", (rid,)).fetchone()
    return dict(r) if r else None


def consume_token(jti, rid, approver):
    """Single use: True only for the first caller that presents this token id."""
    with _conn() as c:
        return _x(
            c,
            "INSERT INTO approval_tokens(jti,request_id,approver,used_at) VALUES(?,?,?,?) ON CONFLICT(jti) DO NOTHING",
            (jti, rid, approver, time.time()),
        ).rowcount == 1


def audit(actor, event, detail="", request_id=None, plan_hash=None):
    with _conn() as c:
        _x(
            c,
            "INSERT INTO audit(ts,actor,event,detail,request_id,plan_hash) VALUES(?,?,?,?,?,?)",
            (time.time(), actor, event, str(detail)[:2000], request_id, plan_hash),
        )


def audit_log(limit=100):
    with _conn() as c:
        return [dict(r) for r in _x(c, "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
