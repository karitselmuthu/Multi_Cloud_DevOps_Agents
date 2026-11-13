"""Secure MCP & policy gateway: the ONLY path from agents to execution systems.
Every call is policy-checked and audited. Mutations need a valid single-use approval token bound to the exact plan.
Real execution happens only in the executor process (ROLE=executor) with EXECUTE=1; everywhere else it is a dry run."""
import base64
import json
import os
import pathlib
import re
import subprocess
import tempfile

import httpx

from . import approval, db, obs, policy

WRITE_TOOLS = {"terraform.apply", "kubectl.apply", "github.create_pr"}
READ_TOOLS = {"terraform.plan"}
K8S_DENY = [
    (r"hostNetwork:\s*true|hostPID:\s*true|hostPath:", "host namespaces/paths are forbidden"),
    (r"kind:\s*(ClusterRole|ClusterRoleBinding|Namespace|CustomResourceDefinition)\b", "cluster-scoped kinds are forbidden"),
]


class PolicyDenied(Exception):
    pass


class ApprovalRejected(PolicyDenied):
    """Token or plan problem: nothing ran and the request goes back to awaiting approval."""


def _allowed_namespaces():
    return set(os.getenv("K8S_ALLOWED_NAMESPACES", "apps").split(","))


def _blob(args):
    return base64.b64decode(args.get("plan_blob") or "")


def check_policy(tool, args, token=None):
    """Returns the verified approval claims for mutating tools, else None."""
    if tool not in WRITE_TOOLS | READ_TOOLS:
        raise PolicyDenied(f"tool not allow-listed: {tool}")
    if args.get("cloud") not in ("aws", "azure"):
        raise PolicyDenied("cloud must be aws or azure")
    if args.get("cloud") == "azure" and tool in WRITE_TOOLS - {"github.create_pr"}:  # a PR is just a proposal
        raise PolicyDenied("azure execution not enabled yet")
    if tool == "github.create_pr":
        if not os.getenv("GITHUB_REPO") or args.get("repo") != os.getenv("GITHUB_REPO"):
            raise PolicyDenied("repo is not the configured GITHUB_REPO")
        if not re.fullmatch(r"requests/[A-Za-z0-9._/-]+", args.get("path", "")) or ".." in args["path"]:
            raise PolicyDenied("path must stay under requests/")
        if not re.fullmatch(r"agent/[a-z0-9-]+", args.get("branch", "")):
            raise PolicyDenied("branch must be agent/<slug>")
    content = args.get("content", "")
    if tool.startswith("kubectl"):
        if args.get("namespace") not in _allowed_namespaces():
            raise PolicyDenied(f"namespace not allowed: {args.get('namespace')}")
        for rx, why in K8S_DENY:
            if re.search(rx, content):
                raise PolicyDenied(why)
        for ns in re.findall(r"^\s*namespace:\s*(\S+)", content, re.M):  # no escaping via metadata.namespace
            if ns not in _allowed_namespaces():
                raise PolicyDenied(f"manifest namespace not allowed: {ns}")
    # defence in depth: re-scan what is about to run, even though the pipeline scanned it earlier
    bad = [f["rule"] + (f":{f['detail']}" if "detail" in f else "") for f in policy.scan(content, "kubernetes" if tool.startswith("kubectl") else "terraform") if f["severity"] == "high"]
    if bad:
        raise PolicyDenied("blocked by policy: " + ", ".join(bad))
    if tool not in WRITE_TOOLS:
        return None
    try:
        return approval.verify(token, args.get("request_id"), policy.plan_hash(content, _blob(args)))
    except approval.TokenInvalid as e:
        raise ApprovalRejected(str(e))


def _deny(tool, actor, rid, e):
    db.audit(actor, "mcp.denied", f"{tool}: {e}", request_id=rid)
    obs.inc("mcp_denied_total", tool=tool)
    obs.log("mcp.denied", tool=tool, actor=actor, request_id=rid, reason=str(e))


def call(tool, args, token=None, actor="agent"):
    rid = args.get("request_id")
    try:
        claims = check_policy(tool, args, token)
        if claims and not db.consume_token(claims["jti"], claims["rid"], claims["sub"]):
            raise ApprovalRejected("approval token already used")
    except PolicyDenied as e:
        _deny(tool, actor, rid, e)
        raise
    real = os.getenv("EXECUTE") == "1" and os.getenv("ROLE") == "executor" and args.get("cloud") == "aws"
    db.audit(actor, "mcp.call", f"{tool} dry_run={not real} approval={claims['jti'] if claims else '-'} approver={claims['sub'] if claims else '-'}",
             request_id=rid, plan_hash=claims["ph"] if claims else None)
    obs.inc("mcp_calls_total", tool=tool, dry_run=str(not real).lower())
    obs.log("mcp.call", tool=tool, actor=actor, request_id=rid, dry_run=not real)
    if not real:
        if tool == "terraform.plan":
            return {"dry_run": True, "plan_blob": "", "summary": policy.summary(args["content"])}
        return {"dry_run": True, "tool": tool, "note": "real execution only in the executor role with EXECUTE=1"}
    if tool == "github.create_pr":
        return _github_pr(args)
    if tool.startswith("kubectl"):
        work = pathlib.Path(tempfile.mkdtemp(prefix="agent-"))
        (work / "manifest.yaml").write_text(args["content"])
        return _run(["kubectl", "apply", "-n", args["namespace"], "-f", "manifest.yaml"], work)
    return _terraform(tool, args)


# ---- GitHub ----
def _http():  # factory so tests can inject a mock transport
    return httpx.Client(
        base_url="https://api.github.com", timeout=30,
        headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}", "Accept": "application/vnd.github+json"},
    )


def _github_pr(a):
    """Branch -> commit file -> open PR. Never pushes to the default branch."""
    with _http() as c:
        def ok(r):
            r.raise_for_status()
            return r.json()

        repo = a["repo"]
        base = ok(c.get(f"/repos/{repo}"))["default_branch"]
        sha = ok(c.get(f"/repos/{repo}/git/ref/heads/{base}"))["object"]["sha"]
        ok(c.post(f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{a['branch']}", "sha": sha}))
        ok(c.put(f"/repos/{repo}/contents/{a['path']}", json={
            "message": a["title"], "branch": a["branch"], "content": base64.b64encode(a["content"].encode()).decode()}))
        pr = ok(c.post(f"/repos/{repo}/pulls", json={"title": a["title"], "head": a["branch"], "base": base, "body": a["body"]}))
        return {"pr_url": pr["html_url"]}


# ---- subprocesses (never inherit the executor's secrets) ----
def _clean_env():
    keep = ("PATH", "AWS_", "TF_", "HOME", "TMPDIR", "LANG")
    env = {k: v for k, v in os.environ.items() if k.startswith(keep) and k not in ("TF_BACKEND",)}
    env["TF_IN_AUTOMATION"] = "1"
    return env


def _sh(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900, env=_clean_env())


def _run(cmd, cwd):
    p = _sh(cmd, cwd)
    return {"rc": p.returncode, "out": (p.stdout + p.stderr)[-3000:]}


# ---- Terraform: plan to a saved file, apply exactly that file ----
def _backend(rid):
    if os.getenv("TF_BACKEND") == "local":  # local dev / tests only
        d = pathlib.Path(os.getenv("TF_LOCAL_STATE_DIR") or pathlib.Path(tempfile.gettempdir()) / "devops-agent-state")
        d.mkdir(parents=True, exist_ok=True)
        return f'terraform {{\n  backend "local" {{\n    path = "{d}/{int(rid)}.tfstate"\n  }}\n}}\n'
    return (
        'terraform {\n  backend "s3" {\n'
        f'    bucket       = "{os.environ["TF_STATE_BUCKET"]}"\n    key          = "requests/{int(rid)}/terraform.tfstate"\n'
        f'    region       = "{os.getenv("AWS_REGION", "us-east-1")}"\n    encrypt      = true\n    use_lockfile = true\n  }}\n}}\n'
    )


def _provider(rid):
    return (
        'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n  }\n}\n'
        f'provider "aws" {{\n  region = "{os.getenv("AWS_REGION", "us-east-1")}"\n'
        f'  default_tags {{\n    tags = {{ request_id = "{int(rid)}", managed_by = "devops-agent" }}\n  }}\n}}\n'
    )


def plan_summary(show_json):
    ch = json.loads(show_json).get("resource_changes", [])
    acts = [(c["address"], c["change"]["actions"]) for c in ch if c["change"]["actions"] != ["no-op"]]
    return {
        "dry_run": False, "changes": [{"address": a, "actions": x} for a, x in acts],
        "adds": sum("create" in x for _, x in acts), "deletes": sum("delete" in x for _, x in acts),
    }


def _terraform(tool, args):
    tf, rid, work = os.getenv("TERRAFORM_BIN", "terraform"), int(args["request_id"]), pathlib.Path(tempfile.mkdtemp(prefix="agent-"))
    (work / "main.tf").write_text(args["content"])
    (work / "backend.tf").write_text(_backend(rid))
    if re.search(r"\baws_", args["content"]):
        (work / "provider.tf").write_text(_provider(rid))
    init = _run([tf, "init", "-input=false", "-no-color"], work)
    if init["rc"]:
        return {"error": "terraform init failed: " + init["out"]}
    lock = "-lock-timeout=60s"
    if tool == "terraform.plan":
        p = _run([tf, "plan", "-input=false", "-no-color", lock, "-out=tfplan"], work)
        if p["rc"]:
            return {"error": "terraform plan failed: " + p["out"]}
        shown = _sh([tf, "show", "-json", "tfplan"], work)
        return {"plan_blob": base64.b64encode((work / "tfplan").read_bytes()).decode(), "summary": plan_summary(shown.stdout)}
    (work / "tfplan").write_bytes(_blob(args))  # the exact bytes whose hash the approver signed off
    shown = _sh([tf, "show", "-json", "tfplan"], work)
    if shown.returncode:
        return {"error": "saved plan is unreadable or stale: " + shown.stderr[-500:]}
    deletes = plan_summary(shown.stdout)["deletes"]
    if deletes > int(os.getenv("TF_MAX_DESTROY", "0")):  # blast-radius limit
        raise PolicyDenied(f"plan destroys {deletes} resource(s); limit is {os.getenv('TF_MAX_DESTROY', '0')}")
    return _run([tf, "apply", "-input=false", "-no-color", lock, "tfplan"], work)
