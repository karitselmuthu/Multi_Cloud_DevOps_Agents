"""Enterprise control plane (FastAPI): request intake, approval workflow, audit, metrics, dashboard."""
import os
import pathlib
import secrets
from collections import Counter

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from . import agents, db, mcp

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


@app.post("/requests", dependencies=[Depends(auth)], status_code=202)
def create_request(r: NewRequest, bg: BackgroundTasks):
    if r.cloud not in ("aws", "azure"):
        raise HTTPException(422, "cloud must be aws or azure")
    if r.kind not in ("terraform", "kubernetes"):
        raise HTTPException(422, "kind must be terraform or kubernetes")
    rid = db.create(r.title, r.description, r.cloud, r.kind)
    db.audit("user", "request.created", f"id={rid}")
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
def approve(rid: int):
    req = db.get(rid) or _404()
    if not db.claim(rid, "pending_approval", "applying"):  # atomic: concurrent approvals can't both run
        raise HTTPException(409, f"status is {req['status']}")
    db.audit("approver", "request.approved", f"id={rid}")
    tool, key = ("kubectl.apply", "kubernetes") if req["kind"] == "kubernetes" else ("terraform.apply", "terraform")
    args = {"cloud": req["cloud"], "content": req["outputs"][key], "namespace": "apps"}
    try:
        result = mcp.call(tool, args, approved=True, actor=f"request-{rid}")
    except mcp.PolicyDenied as e:
        db.update(rid, status="failed", outputs={**req["outputs"], "error": str(e)})
        raise HTTPException(403, str(e))
    db.update(rid, status="applied", outputs={**req["outputs"], "apply": result})
    return result


@app.post("/requests/{rid}/reject", dependencies=[Depends(auth)])
def reject(rid: int):
    req = db.get(rid) or _404()
    if req["status"] not in ("pending_approval", "blocked"):
        raise HTTPException(409, f"status is {req['status']}")
    db.update(rid, status="rejected")
    db.audit("approver", "request.rejected", f"id={rid}")
    return {"ok": True}


@app.get("/audit", dependencies=[Depends(auth)])
def audit():
    return db.audit_log()


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    c = Counter(r["status"] for r in db.list_all())
    return "\n".join(f'devops_requests{{status="{s}"}} {n}' for s, n in c.items()) + "\n"
