"""Temporal activities (side effects live here; the workflow file stays import-free for the sandbox)."""
from temporalio import activity

from . import agents, db, mcp


@activity.defn
def run_pipeline(rid: int) -> str:
    agents.run_pipeline(rid, raise_errors=True)
    return db.get(rid)["status"]


@activity.defn
def apply(rid: int) -> str:
    try:
        agents.apply_request(rid)
    except (agents.Conflict, mcp.PolicyDenied):
        pass  # recorded on the request/audit log; retrying cannot help
    return db.get(rid)["status"]


@activity.defn
def expire(rid: int) -> str:
    db.claim(rid, "pending_approval", "expired")
    return db.get(rid)["status"]


ALL = [run_pipeline, apply, expire]
