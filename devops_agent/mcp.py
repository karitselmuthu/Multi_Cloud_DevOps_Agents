"""Secure MCP & policy gateway: the ONLY path from agents to execution systems.
Every call is policy-checked and audited. Execution is dry-run unless EXECUTE=1."""
import os
import pathlib
import re
import subprocess
import tempfile

from . import db

WRITE_TOOLS = {"terraform.apply", "kubectl.apply"}
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
    if args.get("cloud") == "azure" and tool in WRITE_TOOLS:
        raise PolicyDenied("azure execution not enabled yet")
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


def _run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900)
    return {"rc": p.returncode, "out": (p.stdout + p.stderr)[-3000:]}


def call(tool, args, approved=False, actor="agent"):
    try:
        check_policy(tool, args, approved)
    except PolicyDenied as e:
        db.audit(actor, "mcp.denied", f"{tool}: {e}")
        raise
    db.audit(actor, "mcp.call", f"{tool} dry_run={os.getenv('EXECUTE') != '1'}")
    if os.getenv("EXECUTE") != "1":
        return {"dry_run": True, "tool": tool, "note": "set EXECUTE=1 to run for real"}
    work = pathlib.Path(tempfile.mkdtemp(prefix="agent-"))
    (work / ("main.tf" if tool.startswith("terraform") else "manifest.yaml")).write_text(args["content"])
    if tool == "terraform.plan":
        return _run(["terraform", "init", "-input=false"], work) | {"plan": _run(["terraform", "plan", "-input=false"], work)}
    if tool == "terraform.apply":
        return _run(["terraform", "init", "-input=false"], work) | {"apply": _run(["terraform", "apply", "-auto-approve", "-input=false"], work)}
    return _run(["kubectl", "apply", "-n", args["namespace"], "-f", "manifest.yaml"], work)
