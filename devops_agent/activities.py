"""Temporal activities. AGENT activities run on the agents worker, EXEC ones on the executor worker."""
from temporalio import activity

from . import agents, db, mcp


@activity.defn
def run_pipeline(rid: int) -> str:
    agents.run_pipeline(rid, raise_errors=True, then_plan=False)
    return db.get(rid)["status"]


@activity.defn
def expire(rid: int) -> str:
    db.claim(rid, "pending_approval", "expired")
    return db.get(rid)["status"]


@activity.defn
def plan(rid: int) -> str:
    agents.plan_request(rid)
    return db.get(rid)["status"]


@activity.defn
def apply(rid: int, token: str) -> str:
    try:
        agents.apply_request(rid, token)
    except (agents.Conflict, mcp.PolicyDenied):
        pass  # recorded on the request/audit log; retrying cannot help
    return db.get(rid)["status"]


AGENT = [run_pipeline, expire]
EXEC = [plan, apply]
