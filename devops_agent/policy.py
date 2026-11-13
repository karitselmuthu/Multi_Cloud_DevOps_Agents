"""Static policy for agent-generated artifacts, shared by the pipeline (blocks before approval) and the MCP gateway
(re-checks before anything runs). Terraform uses an ALLOW-list of block and resource types, not just a deny-list:
anything we did not explicitly expect (provider, module, backend, data "external", provisioners...) is rejected.
ponytail: regex + a tiny HCL block scanner, not a full HCL parser; add Checkov/Conftest on the real plan JSON when
policy ownership moves to a security team."""
import fnmatch
import hashlib
import os
import re

SECURITY_RULES = [  # (rule id, regex, severity); "high" blocks the request
    ("open-ingress", r"0\.0\.0\.0/0|::/0", "high"),
    ("public-s3-acl", r'acl\s*=\s*"public', "high"),
    ("s3-public-access-off", r"(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false", "high"),
    ("public-principal", r'"Principal"\s*:\s*(\{\s*"AWS"\s*:\s*)?"\*"|identifiers\s*=\s*\[\s*"\*"\s*\]', "high"),
    ("iam-wildcard", r'"Action"\s*:\s*(\[\s*)?"\*"|actions\s*=\s*\[\s*"\*"\s*\]', "high"),
    ("hardcoded-secret", r'(?i)(password|secret|access_key)\s*=\s*"[^"$]{4,}"', "high"),
    ("public-database", r"publicly_accessible\s*=\s*true", "high"),
    ("provisioner", r"\bprovisioner\b", "high"),
    ("local-file-read", r"\b(file|templatefile|filebase64|filemd5|filesha1|filesha256|filesha512|fileset|pathexpand)\s*\(", "high"),
    ("k8s-privileged", r"privileged:\s*true", "high"),
    ("k8s-run-as-root", r"runAsNonRoot:\s*false", "high"),
    ("k8s-latest-tag", r"image:\s*\S+:latest\b", "medium"),
    ("k8s-no-limits", r"kind:\s*Deployment(?![\s\S]*limits:)", "medium"),
    ("no-encryption", r"(?i)encrypted\s*=\s*false", "medium"),
]
DEFAULT_RESOURCES = (
    "aws_s3_bucket,aws_s3_bucket_*,aws_ecr_repository,aws_ecr_lifecycle_policy,aws_cloudwatch_log_group,aws_sqs_queue,"
    "aws_sns_topic,aws_dynamodb_table,azurerm_resource_group,azurerm_storage_account,azurerm_storage_container"
)
DEFAULT_DATA = "aws_caller_identity,aws_region,aws_partition"
PLAIN_BLOCKS = {"variable", "output", "locals"}
HEREDOC = re.compile(r"<<-?\s*([A-Za-z_]\w*)\n")


def _skip_str(t, i):
    """t[i] == '"'. Index after the closing quote, honouring escapes and ${...} interpolation."""
    i, n = i + 1, len(t)
    while i < n:
        if t[i] == "\\":
            i += 2
        elif t[i] == '"':
            return i + 1
        elif t.startswith(("${", "%{"), i):
            j = _skip_braces(t, i + 1)
            i = n if j < 0 else j
        else:
            i += 1
    return n


def _skip_braces(t, i):
    """t[i] == '{'. Index after the matching '}', or -1 if unbalanced."""
    d, n = 0, len(t)
    while i < n:
        c = t[i]
        if c == '"':
            i = _skip_str(t, i)
        elif t.startswith(("#", "//"), i):
            j = t.find("\n", i)
            i = n if j < 0 else j
        elif t.startswith("/*", i):
            j = t.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif m := HEREDOC.match(t, i):
            end = re.compile(r"^\s*" + re.escape(m.group(1)) + r"\s*$", re.M).search(t, m.end())
            i = n if not end else end.end()
        else:
            d += (c == "{") - (c == "}")
            i += 1
            if d == 0:
                return i
    return -1


def top_level_blocks(t):
    """[(block_type, [labels])]. '=' marks a top-level attribute and '?' anything malformed (fail closed)."""
    out, i, n, head = [], 0, len(t), ""
    while i < n:
        c = t[i]
        if t.startswith(("#", "//"), i):
            j = t.find("\n", i)
            i = n if j < 0 else j
        elif t.startswith("/*", i):
            j = t.find("*/", i + 2)
            if j < 0:
                return out + [("?", [])]
            i = j + 2
        elif c == '"':
            j = _skip_str(t, i)
            head += t[i:j]
            i = j
        elif c == "{":
            j = _skip_braces(t, i)
            m = re.fullmatch(r'\s*(\w+)((?:\s+"[^"]*")*)\s*', head)
            if j < 0 or not m:
                return out + [("?", [])]
            out.append((m.group(1), re.findall(r'"([^"]*)"', m.group(2))))
            head, i = "", j
        elif c == "\n":
            if head.strip():
                out.append(("=" if "=" in head else "?", []))
            head, i = "", i + 1
        else:
            head += c
            i += 1
    return out + ([("?", [])] if head.strip() else [])


def _patterns(var, default):
    return [p.strip() for p in os.getenv(var, default).split(",") if p.strip()]


def _allowed(name, patterns):
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def check_structure(text):
    found, res, data = [], _patterns("TF_ALLOWED_RESOURCES", DEFAULT_RESOURCES), _patterns("TF_ALLOWED_DATA", DEFAULT_DATA)
    for kind, labels in top_level_blocks(text):
        name = labels[0] if labels else ""
        if kind in ("=", "?"):
            found.append({"rule": "malformed-or-top-level-attribute", "severity": "high"})
        elif kind in PLAIN_BLOCKS:
            continue
        elif kind == "resource" and not _allowed(name, res):
            found.append({"rule": "disallowed-resource-type", "severity": "high", "detail": name})
        elif kind == "data" and not _allowed(name, data):
            found.append({"rule": "disallowed-data-source", "severity": "high", "detail": name})
        elif kind not in ("resource", "data"):
            found.append({"rule": "disallowed-block", "severity": "high", "detail": kind})
    return found


def scan(code, kind="terraform"):
    found = [{"rule": r, "severity": s} for r, rx, s in SECURITY_RULES if re.search(rx, code)]
    if kind in ("terraform", "github"):
        found += check_structure(code)
    return found


def plan_hash(content, blob=b""):
    """What an approver is really approving: the artifact plus (for Terraform) the exact saved plan file."""
    return hashlib.sha256(content.encode() + b"\0" + blob).hexdigest()


def summary(content, kind="terraform"):
    """Offline description of what the artifact would create (shown to the approver; replaced by the real plan when one exists)."""
    if kind == "kubernetes":
        return {"dry_run": True, "kinds": re.findall(r"^kind:\s*(\w+)", content, re.M)}
    res = [f"{lb[0]}.{lb[1]}" for k, lb in top_level_blocks(content) if k == "resource" and len(lb) > 1]
    return {"dry_run": True, "resources": res, "adds": len(res), "deletes": 0}
