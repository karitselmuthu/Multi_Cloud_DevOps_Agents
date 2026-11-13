"""Secure MCP & policy gateway: the ONLY path from agents to execution systems.
Every call is policy-checked and audited. Execution is dry-run unless EXECUTE=1."""
import os
import pathlib
import subprocess
import tempfile

from . import db

WRITE_TOOLS = {"terraform.apply", "kubectl.apply"}
READ_TOOLS = {"terraform.plan"}


class PolicyDenied(Exception):
    pass


def check_policy(tool, args, approved):
    """OPA-style deny rules (ponytail: plain Python; move to Rego/OPA when policies are owned by security)."""
    if tool not in WRITE_TOOLS | READ_TOOLS:
        raise PolicyDenied(f"tool not allow-listed: {tool}")
    if tool in WRITE_TOOLS and not approved:
        raise PolicyDenied(f"{tool} requires human approval")
    if args.get("cloud") not in ("aws", "azure"):
        raise PolicyDenied("cloud must be aws or azure")
    if args.get("cloud") == "azure" and tool in WRITE_TOOLS:
        raise PolicyDenied("azure execution not enabled yet")


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
    return _run(["kubectl", "apply", "-f", "manifest.yaml"], work)
