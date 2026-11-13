"""Enterprise control plane (FastAPI): request intake, identity + approval workflow, audit, metrics, dashboard.
Users come from API_USERS = {"<api key>": {"user": "alice", "roles": ["requester"]}} (roles: requester, approver).
ponytail: static per-user keys; swap `auth` for OIDC/JWT validation when an IdP is available."""
import asyncio
import json
import os
import pathlib
import secrets
import time
from collections import Counter

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from . import agents, approval, db, mcp, obs, workflows

app = FastAPI(title="Multi-Cloud DevOps Agents")
KINDS = ("terraform", "kubernetes", "github")


@app.middleware("http")
async def access_log(request, call_next):
    t0 = time.time()
    resp = await call_next(request)
    route = getattr(request.scope.get("route"), "path", "unmatched")  # template, not raw path: bounded label cardinality
    obs.inc("http_requests_total", route=route, method=request.method, status=resp.status_code)
    if route != "/healthz":
        obs.log("http", route=route, method=request.method, status=resp.status_code, ms=int((time.time() - t0) * 1000))
    return resp


def auth(x_api_key: str = Header(default="")):
    try:
        users = json.loads(os.getenv("API_USERS", "{}"))
    except ValueError:
        users = {}
    if not users:
        raise HTTPException(503, "API_USERS is not configured")
    found = None
    for key, u in users.items():  # no early exit: constant work per key
        if secrets.compare_digest(x_api_key.encode(), key.encode()):
            found = u
    if not found:
        raise HTTPException(401, "bad api key")
    return {"user": found["user"], "roles": set(found.get("roles", []))}


def need(role):
    def dep(u=Depends(auth)):
        if role not in u["roles"]:
            raise HTTPException(403, f"requires role {role}")
        return u

    return dep


class NewRequest(BaseModel):
    title: str
    description: str = ""
    cloud: str = "aws"
    kind: str = "terraform"  # terraform | kubernetes | github (PR to GITHUB_REPO)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def ui():
    return FileResponse(pathlib.Path(__file__).parent / "static" / "index.html")


_tc = None


async def _temporal():
    """Temporal client when TEMPORAL_ADDRESS is set, else None (in-process, dry-run only)."""
    global _tc
    if not os.getenv("TEMPORAL_ADDRESS"):
        return None
    if _tc is None:
        _tc = await workflows.connect()
    return _tc


def _visible(req, u):
    return "approver" in u["roles"] or req["requester"] == u["user"]


@app.post("/requests", status_code=202)
async def create_request(r: NewRequest, bg: BackgroundTasks, u=Depends(need("requester"))):
    if r.cloud not in ("aws", "azure"):
        raise HTTPException(422, "cloud must be aws or azure")
    if r.kind not in KINDS:
        raise HTTPException(422, "kind must be terraform, kubernetes or github")
    rid = await asyncio.to_thread(db.create, r.title, r.description, r.cloud, r.kind, u["user"])
    db.audit(u["user"], "request.created", f"id={rid}", request_id=rid)
    if tc := await _temporal():
        await tc.start_workflow(workflows.RequestWorkflow.run, rid, id=f"request-{rid}", task_queue=workflows.AGENTS_QUEUE)
    else:
        bg.add_task(agents.run_pipeline, rid)
    return {"id": rid}


@app.get("/requests")
def list_requests(u=Depends(auth)):
    return db.list_all(None if "approver" in u["roles"] else u["user"])


def _404():
    raise HTTPException(404, "not found")


@app.get("/requests/{rid}")
def get_request(rid: int, u=Depends(auth)):
    req = db.get(rid)
    return req if req and _visible(req, u) else _404()  # 404, not 403: don't reveal other users' ids


@app.post("/requests/{rid}/approve")
async def approve(rid: int, u=Depends(need("approver"))):
    req = db.get(rid) or _404()
    if req["requester"] == u["user"]:  # separation of duties, enforced here and not just hidden in the UI
        db.audit(u["user"], "request.approve_denied", "self-approval attempt", request_id=rid)
        obs.inc("approvals_denied_total", reason="self_approval")
        raise HTTPException(403, "requester cannot approve their own request")
    plan = db.get_plan(rid)
    if req["status"] != "pending_approval" or not plan:
        raise HTTPException(409, f"status is {req['status']}")
    try:
        token = approval.mint(rid, plan["plan_hash"], u["user"])
    except approval.TokenInvalid as e:
        raise HTTPException(503, str(e))
    db.audit(u["user"], "request.approved", f"id={rid}", request_id=rid, plan_hash=plan["plan_hash"])
    if tc := await _temporal():  # the executor's apply activity does the claim + gateway call
        await tc.get_workflow_handle(f"request-{rid}").signal(workflows.RequestWorkflow.decide, workflows.Decision(True, token))
        return {"signalled": "approve"}
    try:
        return await asyncio.to_thread(agents.apply_request, rid, token)  # in-process mode: dry-run only
    except (agents.Conflict, mcp.ApprovalRejected) as e:
        raise HTTPException(409, str(e))
    except mcp.PolicyDenied as e:
        raise HTTPException(403, str(e))


@app.post("/requests/{rid}/reject")
async def reject(rid: int, u=Depends(auth)):
    req = db.get(rid) or _404()
    if not _visible(req, u):
        _404()
    if not (db.claim(rid, "pending_approval", "rejected") or db.claim(rid, "blocked", "rejected")):
        raise HTTPException(409, f"status is {db.get(rid)['status']}")
    db.audit(u["user"], "request.rejected", f"id={rid}", request_id=rid)
    if tc := await _temporal():
        try:
            await tc.get_workflow_handle(f"request-{rid}").signal(workflows.RequestWorkflow.decide, workflows.Decision(False))
        except Exception:  # noqa: BLE001 - workflow already finished (e.g. blocked request); nothing to wake
            pass
    return {"ok": True}


@app.get("/audit", dependencies=[Depends(need("approver"))])
def audit():
    return db.audit_log()


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    c = Counter(r["status"] for r in db.list_all())
    return "".join(f'devops_requests{{status="{s}"}} {n}\n' for s, n in c.items()) + obs.render()
