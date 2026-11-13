"""Agent orchestration: Planning -> Infrastructure -> Code -> Security -> DevOps -> Monitoring.
ponytail: a plain sequential runner instead of LangGraph/Temporal; each stage is state-in/text-out so
porting to LangGraph nodes later is mechanical. Agents only *propose*; execution goes through mcp.py."""
import base64
import json
import os
import re

from . import db, llm, mcp, policy, rag
from .policy import scan  # noqa: F401 - re-exported: rules live in policy.py

TF_TEMPLATE = {
    "aws": 'resource "aws_s3_bucket" "this" {\n  bucket = "{name}"\n}\n'
    'resource "aws_s3_bucket_public_access_block" "this" {\n  bucket = aws_s3_bucket.this.id\n'
    "  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}\n",
    "azure": 'resource "azurerm_resource_group" "this" {\n  name     = "{name}"\n  location = "eastus"\n}\n',
}

K8S_TEMPLATE = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: apps
spec:
  replicas: 2
  selector:
    matchLabels: {app: {name}}
  template:
    metadata:
      labels: {app: {name}}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 10001}
      containers:
        - name: app
          image: public.ecr.aws/nginx/nginx-unprivileged:1.27
          ports: [{containerPort: 8080}]
          resources:
            requests: {cpu: 50m, memory: 64Mi}
            limits: {cpu: 250m, memory: 128Mi}
          readinessProbe: {httpGet: {path: /, port: 8080}}
          livenessProbe: {httpGet: {path: /, port: 8080}}
"""

def _slug(s):
    return re.sub(r"[^a-z0-9-]", "-", s.lower())[:40].strip("-") or "app"


def _ask(stage, req, context):
    return llm.complete(
        f"Request: {req['title']}\n{req['description']}\nTarget cloud: {req['cloud']}\n\nContext:\n{context}",
        system=f"You are the {stage} agent of a multi-cloud DevOps platform. Be concise and follow the standards in context.",
        stage=stage,
    )


def run_pipeline(rid, raise_errors=False, then_plan=True):
    req = db.get(rid)
    db.update(rid, status="running")
    out = {}
    try:
        kb = "\n".join(rag.search(f"{req['title']} {req['description']} {req['cloud']}"))
        out["context"] = kb
        out["plan"] = _ask("planning", req, kb)
        if req["kind"] == "kubernetes":
            man = _ask("kubernetes", req, f"{kb}\nPlan:\n{out['plan']}\nReturn a manifest in a ```yaml block.")
            m = re.search(r"```ya?ml\n(.*?)```", man, re.S)
            out["kubernetes"] = m.group(1) if m else K8S_TEMPLATE.replace("{name}", _slug(req["title"]))
            artifact = out["kubernetes"]
        else:
            infra = _ask("infrastructure", req, f"{kb}\nPlan:\n{out['plan']}\nReturn Terraform in a ```hcl block.")
            m = re.search(r"```hcl\n(.*?)```", infra, re.S)
            out["terraform"] = m.group(1) if m else TF_TEMPLATE[req["cloud"]].replace("{name}", _slug(req["title"]))
            artifact = out["terraform"]
        out["code"] = _ask("code", req, f"Artifact:\n{artifact}")
        out["findings"] = scan(artifact, "kubernetes" if req["kind"] == "kubernetes" else "terraform")
        out["security"] = _ask("security", req, f"Findings: {out['findings']}")
        out["devops"] = _ask("devops", req, "Describe the CI/CD steps to deploy this.")
        out["monitoring"] = _ask("monitoring", req, "Propose alerts and dashboards.")
        blocked = any(f["severity"] == "high" for f in out["findings"])
        db.update(rid, status="blocked" if blocked else "planning", outputs=out)
        db.audit("agents", "pipeline.done", f"request={rid} blocked={blocked}", request_id=rid)
        if not blocked and then_plan:  # Temporal mode runs the plan step on the executor instead
            plan_request(rid)
    except Exception as e:  # noqa: BLE001 - surface any stage failure on the request
        out["error"] = str(e)
        db.update(rid, status="failed", outputs=out)
        db.audit("agents", "pipeline.failed", f"request={rid}: {e}")
        if raise_errors:  # Temporal retries the activity; plain mode just records the failure
            raise


class Conflict(Exception):
    """Request is not in a state that can be applied (already applied, rejected, expired...)."""


def _artifact(req):
    return ("kubernetes", "kubectl.apply") if req["kind"] == "kubernetes" else ("terraform", "github.create_pr" if req["kind"] == "github" else "terraform.apply")


def plan_request(rid):
    """Produce the exact thing a human will approve: the artifact plus (terraform) a saved plan file. Stores its hash."""
    req = db.get(rid)
    key, _ = _artifact(req)
    content = req["outputs"][key]
    blob_b64, summ = "", policy.summary(content, key)
    if req["kind"] == "terraform":
        try:
            res = mcp.call("terraform.plan", {"cloud": req["cloud"], "content": content, "request_id": rid}, actor=f"request-{rid}")
        except mcp.PolicyDenied as e:
            res = {"error": str(e)}
        if "error" in res:
            db.update(rid, status="failed", outputs={**req["outputs"], "error": res["error"]})
            return
        blob_b64, summ = res.get("plan_blob", ""), res.get("summary") or summ
    ph = policy.plan_hash(content, base64.b64decode(blob_b64))
    db.set_plan(rid, ph, blob_b64, json.dumps(summ))
    db.update(rid, status="pending_approval", outputs={**req["outputs"], "plan_summary": summ, "plan_hash": ph})
    db.audit("agents", "plan.ready", f"request={rid}", request_id=rid, plan_hash=ph)


def apply_request(rid, token):
    """Approved execution, shared by the HTTP path and the Temporal activity. Raises Conflict / mcp.PolicyDenied.
    The gateway verifies the token against the plan hash it recomputes from what it is about to run."""
    req = db.get(rid)
    if not db.claim(rid, "pending_approval", "applying"):  # atomic: concurrent approvals can't both run
        raise Conflict(f"status is {req['status'] if req else 'missing'}")
    key, tool = _artifact(req)
    plan = db.get_plan(rid) or {"blob": ""}
    args = {"cloud": req["cloud"], "content": req["outputs"][key], "namespace": "apps", "request_id": rid, "plan_blob": plan["blob"]}
    if tool == "github.create_pr":  # deliver as a PR to the GitOps repo instead of applying directly
        args |= {
            "repo": os.getenv("GITHUB_REPO", ""), "path": f"requests/{rid}-{_slug(req['title'])}/main.tf",
            "branch": f"agent/request-{rid}", "title": f"[agent] {req['title']}",
            "body": f"Generated by DevOps agents for request #{rid}. Security findings: {req['outputs'].get('findings')}",
        }
    try:
        result = mcp.call(tool, args, token=token, actor=f"request-{rid}")
    except mcp.ApprovalRejected:
        db.claim(rid, "applying", "pending_approval")  # plan or token problem: a human must approve again
        raise
    except mcp.PolicyDenied as e:
        db.update(rid, status="failed", outputs={**req["outputs"], "error": str(e)})
        raise
    status = "failed" if result.get("error") or result.get("rc") else "pr_opened" if tool == "github.create_pr" else "applied"
    db.update(rid, status=status, outputs={**req["outputs"], "apply": result})
    return result
