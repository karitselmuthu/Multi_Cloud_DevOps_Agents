"""Enterprise control plane (FastAPI): request intake, approval workflow, audit, metrics, dashboard."""
import asyncio
import os
import pathlib
import secrets
from collections import Counter

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from . import agents, db, mcp, workflows

app = FastAPI(title="Multi-Cloud DevOps Agents")


def auth(x_api_key: str = Header(default="")):
    key = os.getenv("API_KEY")  # unset = open (local dev only)
    if key and not secrets.compare_digest(x_api_key, key):
        raise HTTPException(401, "bad api key")


class NewRequest(BaseModel):
    title: str
    description: str = ""
    cloud: str = "aws"
    kind: str = "terraform"  # terraform | kubernetes


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def ui():
    return FileResponse(pathlib.Path(__file__).parent / "static" / "index.html")


_tc = None


async def _temporal():
    """Temporal client when TEMPORAL_ADDRESS is set, else None (in-process fallback)."""
    global _tc
    if not os.getenv("TEMPORAL_ADDRESS"):
        return None
    if _tc is None:
        _tc = await workflows.connect()
    return _tc


@app.post("/requests", dependencies=[Depends(auth)], status_code=202)
async def create_request(r: NewRequest, bg: BackgroundTasks):
    if r.cloud not in ("aws", "azure"):
        raise HTTPException(422, "cloud must be aws or azure")
    if r.kind not in ("terraform", "kubernetes"):
        raise HTTPException(422, "kind must be terraform or kubernetes")
    rid = await asyncio.to_thread(db.create, r.title, r.description, r.cloud, r.kind)
    db.audit("user", "request.created", f"id={rid}")
    if tc := await _temporal():
        await tc.start_workflow(workflows.RequestWorkflow.run, rid, id=f"request-{rid}", task_queue=workflows.TASK_QUEUE)
    else:
        bg.add_task(agents.run_pipeline, rid)
    return {"id": rid}


@app.get("/requests", dependencies=[Depends(auth)])
def list_requests():
    return db.list_all()


@app.get("/requests/{rid}", dependencies=[Depends(auth)])
def get_request(rid: int):
    return db.get(rid) or _404()


def _404():
    raise HTTPException(404, "not found")


@app.post("/requests/{rid}/approve", dependencies=[Depends(auth)])
async def approve(rid: int):
    req = db.get(rid) or _404()
    if req["status"] != "pending_approval":
        raise HTTPException(409, f"status is {req['status']}")
    if tc := await _temporal():  # the workflow's apply activity does the atomic claim + execution
        await tc.get_workflow_handle(f"request-{rid}").signal(workflows.RequestWorkflow.decide, True)
        return {"signalled": "approve"}
    try:
        return await asyncio.to_thread(agents.apply_request, rid)  # blocking subprocess: keep off the event loop
    except agents.Conflict as e:
        raise HTTPException(409, str(e))
    except mcp.PolicyDenied as e:
        raise HTTPException(403, str(e))


@app.post("/requests/{rid}/reject", dependencies=[Depends(auth)])
async def reject(rid: int):
    db.get(rid) or _404()
    if not (db.claim(rid, "pending_approval", "rejected") or db.claim(rid, "blocked", "rejected")):
        raise HTTPException(409, f"status is {db.get(rid)['status']}")
    db.audit("approver", "request.rejected", f"id={rid}")
    if tc := await _temporal():
        try:
            await tc.get_workflow_handle(f"request-{rid}").signal(workflows.RequestWorkflow.decide, False)
        except Exception:  # noqa: BLE001 - workflow already finished (e.g. blocked request); nothing to wake
            pass
    return {"ok": True}


@app.get("/audit", dependencies=[Depends(auth)])
def audit():
    return db.audit_log()


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    c = Counter(r["status"] for r in db.list_all())
    return "\n".join(f'devops_requests{{status="{s}"}} {n}' for s, n in c.items()) + "\n"
