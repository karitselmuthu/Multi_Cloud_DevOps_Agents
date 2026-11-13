"""Secure MCP & policy gateway: the ONLY path from agents to execution systems.
Every call is policy-checked and audited. Execution is dry-run unless EXECUTE=1."""
import base64
import os
import pathlib
import re
import subprocess
import tempfile

import httpx

from . import db, obs

WRITE_TOOLS = {"terraform.apply", "kubectl.apply", "github.create_pr"}
READ_TOOLS = {"terraform.plan"}
K8S_DENY = [  # OPA-style deny rules for manifests (ponytail: regex, move to Rego/OPA when security owns policy)
    (r"privileged:\s*true", "privileged containers are forbidden"),
    (r"hostNetwork:\s*true|hostPID:\s*true|hostPath:", "host namespaces/paths are forbidden"),
    (r"kind:\s*(ClusterRole|ClusterRoleBinding|Namespace|CustomResourceDefinition)\b", "cluster-scoped kinds are forbidden"),
]


class PolicyDenied(Exception):
    pass


def _allowed_namespaces():
    return set(os.getenv("K8S_ALLOWED_NAMESPACES", "apps").split(","))


def check_policy(tool, args, approved):
    if tool not in WRITE_TOOLS | READ_TOOLS:
        raise PolicyDenied(f"tool not allow-listed: {tool}")
    if tool in WRITE_TOOLS and not approved:
        raise PolicyDenied(f"{tool} requires human approval")
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
    if tool.startswith("kubectl"):
        if args.get("namespace") not in _allowed_namespaces():
            raise PolicyDenied(f"namespace not allowed: {args.get('namespace')}")
        for rx, why in K8S_DENY:
            if re.search(rx, args.get("content", "")):
                raise PolicyDenied(why)
        # every namespace named inside the manifest must also be allowed (no escaping via metadata.namespace)
        for ns in re.findall(r"^\s*namespace:\s*(\S+)", args.get("content", ""), re.M):
            if ns not in _allowed_namespaces():
                raise PolicyDenied(f"manifest namespace not allowed: {ns}")


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


def _run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900)
    return {"rc": p.returncode, "out": (p.stdout + p.stderr)[-3000:]}


def call(tool, args, approved=False, actor="agent"):
    try:
        check_policy(tool, args, approved)
    except PolicyDenied as e:
        db.audit(actor, "mcp.denied", f"{tool}: {e}")
        obs.inc("mcp_denied_total", tool=tool)
        obs.log("mcp.denied", tool=tool, actor=actor, reason=str(e))
        raise
    db.audit(actor, "mcp.call", f"{tool} dry_run={os.getenv('EXECUTE') != '1'}")
    obs.inc("mcp_calls_total", tool=tool, dry_run=str(os.getenv("EXECUTE") != "1").lower())
    obs.log("mcp.call", tool=tool, actor=actor, dry_run=os.getenv("EXECUTE") != "1")
    if os.getenv("EXECUTE") != "1":
        return {"dry_run": True, "tool": tool, "note": "set EXECUTE=1 to run for real"}
    if tool == "github.create_pr":
        return _github_pr(args)
    work = pathlib.Path(tempfile.mkdtemp(prefix="agent-"))
    (work / ("main.tf" if tool.startswith("terraform") else "manifest.yaml")).write_text(args["content"])
    if tool == "terraform.plan":
        return _run(["terraform", "init", "-input=false"], work) | {"plan": _run(["terraform", "plan", "-input=false"], work)}
    if tool == "terraform.apply":
        return _run(["terraform", "init", "-input=false"], work) | {"apply": _run(["terraform", "apply", "-auto-approve", "-input=false"], work)}
    return _run(["kubectl", "apply", "-n", args["namespace"], "-f", "manifest.yaml"], work)
