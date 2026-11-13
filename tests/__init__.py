"""Shared test environment (runs once when the tests package is imported)."""
import json
import os
import tempfile

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["APPROVAL_SECRET"] = "test-approval-secret-0123456789"
os.environ["API_USERS"] = json.dumps({
    "ka": {"user": "alice", "roles": ["requester"]},
    "kb": {"user": "bob", "roles": ["approver"]},
    "kc": {"user": "carol", "roles": ["requester", "approver"]},
    "kd": {"user": "dan", "roles": ["requester"]},
})
# in-process tests must not talk to Temporal; test_temporal re-enables it from TEST_TEMPORAL_ADDRESS
os.environ["TEST_TEMPORAL_ADDRESS"] = os.environ.pop("TEMPORAL_ADDRESS", "")
for k in ("EXECUTE", "ROLE"):  # DATABASE_URL is honoured so the suite can run against Postgres
    os.environ.pop(k, None)
