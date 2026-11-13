"""Agent orchestration: Planning -> Infrastructure -> Code -> Security -> DevOps -> Monitoring.
ponytail: a plain sequential runner instead of LangGraph/Temporal; each stage is state-in/text-out so
porting to LangGraph nodes later is mechanical. Agents only *propose*; execution goes through mcp.py."""
import re

from . import db, llm, mcp, rag

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

# (rule id, regex, severity) -- blocking = high
SECURITY_RULES = [
    ("open-ingress", r'0\.0\.0\.0/0', "high"),
    ("public-s3-acl", r'acl\s*=\s*"public', "high"),
    ("iam-wildcard", r'"Action"\s*:\s*"\*"|actions\s*=\s*\["\*"\]', "high"),
    ("hardcoded-secret", r'(?i)(password|secret|access_key)\s*=\s*"[^"$]{4,}"', "high"),
    ("k8s-privileged", r'privileged:\s*true', "high"),
    ("k8s-latest-tag", r'image:\s*\S+:latest\b', "medium"),
    ("k8s-no-limits", r'kind:\s*Deployment(?![\s\S]*limits:)', "medium"),
    ("k8s-run-as-root", r'runAsNonRoot:\s*false', "high"),
    ("no-encryption", r'(?i)encrypted\s*=\s*false', "medium"),
]


def _slug(s):
    return re.sub(r"[^a-z0-9-]", "-", s.lower())[:40].strip("-") or "app"


def scan(code):
    return [{"rule": r, "severity": s} for r, rx, s in SECURITY_RULES if re.search(rx, code)]


def _ask(stage, req, context):
    return llm.complete(
        f"Request: {req['title']}\n{req['description']}\nTarget cloud: {req['cloud']}\n\nContext:\n{context}",
        system=f"You are the {stage} agent of a multi-cloud DevOps platform. Be concise and follow the standards in context.",
    )


def run_pipeline(rid, raise_errors=False):
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
        out["findings"] = scan(artifact)
        out["security"] = _ask("security", req, f"Findings: {out['findings']}")
        out["devops"] = _ask("devops", req, "Describe the CI/CD steps to deploy this.")
        out["monitoring"] = _ask("monitoring", req, "Propose alerts and dashboards.")
        blocked = any(f["severity"] == "high" for f in out["findings"])
        db.update(rid, status="blocked" if blocked else "pending_approval", outputs=out)
        db.audit("agents", "pipeline.done", f"request={rid} blocked={blocked}")
    except Exception as e:  # noqa: BLE001 - surface any stage failure on the request
        out["error"] = str(e)
        db.update(rid, status="failed", outputs=out)
        db.audit("agents", "pipeline.failed", f"request={rid}: {e}")
        if raise_errors:  # Temporal retries the activity; plain mode just records the failure
            raise


class Conflict(Exception):
    """Request is not in a state that can be applied (already applied, rejected, expired...)."""


def apply_request(rid):
    """Approved execution, shared by the HTTP path and the Temporal activity. Raises Conflict / mcp.PolicyDenied."""
    req = db.get(rid)
    if not db.claim(rid, "pending_approval", "applying"):  # atomic: concurrent approvals can't both run
        raise Conflict(f"status is {req['status'] if req else 'missing'}")
    db.audit("approver", "request.approved", f"id={rid}")
    tool, key = ("kubectl.apply", "kubernetes") if req["kind"] == "kubernetes" else ("terraform.apply", "terraform")
    args = {"cloud": req["cloud"], "content": req["outputs"][key], "namespace": "apps"}
    try:
        result = mcp.call(tool, args, approved=True, actor=f"request-{rid}")
    except mcp.PolicyDenied as e:
        db.update(rid, status="failed", outputs={**req["outputs"], "error": str(e)})
        raise
    db.update(rid, status="applied", outputs={**req["outputs"], "apply": result})
    return result
