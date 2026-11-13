import os
import tempfile
import unittest

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ.pop("API_KEY", None)
os.environ.pop("EXECUTE", None)

from fastapi.testclient import TestClient  # noqa: E402

import httpx

from devops_agent import agents, mcp, obs, rag  # noqa: E402
from devops_agent.main import app  # noqa: E402

c = TestClient(app)


class Tests(unittest.TestCase):
    def test_security_scan(self):
        self.assertEqual(agents.scan('cidr = "0.0.0.0/0"')[0]["rule"], "open-ingress")
        self.assertEqual(agents.scan('resource "aws_s3_bucket" "x" {}'), [])

    def test_rag(self):
        self.assertTrue(any("public" in p for p in rag.search("s3 bucket public access")))

    def test_policy(self):
        with self.assertRaises(mcp.PolicyDenied):
            mcp.call("terraform.apply", {"cloud": "aws", "content": ""}, approved=False)
        with self.assertRaises(mcp.PolicyDenied):
            mcp.call("rm.rf", {"cloud": "aws"}, approved=True)

    def test_end_to_end_approve(self):
        rid = c.post("/requests", json={"title": "Logs bucket", "description": "s3", "cloud": "aws"}).json()["id"]
        r = c.get(f"/requests/{rid}").json()  # BackgroundTasks run before TestClient returns
        self.assertEqual(r["status"], "pending_approval")
        self.assertIn("aws_s3_bucket", r["outputs"]["terraform"])
        self.assertTrue(c.post(f"/requests/{rid}/approve").json()["dry_run"])
        self.assertEqual(c.get(f"/requests/{rid}").json()["status"], "applied")
        self.assertEqual(c.post(f"/requests/{rid}/approve").status_code, 409)  # not re-appliable
        self.assertTrue(any(a["event"] == "mcp.call" for a in c.get("/audit").json()))

    def test_kubernetes_flow_and_policy(self):
        rid = c.post("/requests", json={"title": "Web app", "cloud": "aws", "kind": "kubernetes"}).json()["id"]
        r = c.get(f"/requests/{rid}").json()
        self.assertEqual(r["status"], "pending_approval")
        self.assertIn("kind: Deployment", r["outputs"]["kubernetes"])
        self.assertTrue(c.post(f"/requests/{rid}/approve").json()["dry_run"])
        ok = {"cloud": "aws", "namespace": "apps", "content": "kind: Deployment\n"}
        for bad in ({"namespace": "kube-system"}, {"content": "privileged: true"},
                    {"content": "kind: ClusterRoleBinding"}, {"content": "metadata:\n  namespace: kube-system"}):
            with self.assertRaises(mcp.PolicyDenied):
                mcp.call("kubectl.apply", {**ok, **bad}, approved=True)
        self.assertEqual(agents.scan("privileged: true")[0]["rule"], "k8s-privileged")

    def test_github_pr_flow_and_policy(self):
        os.environ["GITHUB_REPO"] = "o/gitops"
        os.environ["GITHUB_TOKEN"] = "t"
        calls = []

        def handler(req):
            calls.append((req.method, req.url.path))
            body = {"/repos/o/gitops": {"default_branch": "main"},
                    "/repos/o/gitops/git/ref/heads/main": {"object": {"sha": "abc"}},
                    "/repos/o/gitops/pulls": {"html_url": "https://github.com/o/gitops/pull/1"}}
            return httpx.Response(200, json=body.get(req.url.path, {}))

        real = mcp._http
        mcp._http = lambda: httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(handler))
        try:
            good = {"cloud": "aws", "repo": "o/gitops", "path": "requests/1-x/main.tf", "branch": "agent/request-1",
                    "title": "t", "body": "b", "content": "x"}
            os.environ["EXECUTE"] = "1"
            self.assertEqual(mcp.call("github.create_pr", good, approved=True)["pr_url"], "https://github.com/o/gitops/pull/1")
            self.assertEqual([m for m, _ in calls], ["GET", "GET", "POST", "PUT", "POST"])
            for bad in ({"repo": "evil/repo"}, {"path": "requests/../.github/workflows/x.yml"},
                        {"path": ".github/workflows/x.yml"}, {"branch": "main"}):
                with self.assertRaises(mcp.PolicyDenied):
                    mcp.call("github.create_pr", {**good, **bad}, approved=True)
            with self.assertRaises(mcp.PolicyDenied):
                mcp.call("github.create_pr", good, approved=False)
        finally:
            mcp._http = real
            for k in ("EXECUTE", "GITHUB_REPO", "GITHUB_TOKEN"):
                os.environ.pop(k, None)

    def test_github_kind_end_to_end(self):
        os.environ["GITHUB_REPO"] = "o/gitops"
        try:
            rid = c.post("/requests", json={"title": "Logs bucket", "cloud": "aws", "kind": "github"}).json()["id"]
            self.assertEqual(c.get(f"/requests/{rid}").json()["status"], "pending_approval")
            self.assertTrue(c.post(f"/requests/{rid}/approve").json()["dry_run"])
            self.assertEqual(c.get(f"/requests/{rid}").json()["status"], "pr_opened")
        finally:
            os.environ.pop("GITHUB_REPO")

    def test_metrics(self):
        c.get("/requests")
        m = c.get("/metrics").text
        self.assertIn('http_requests_total{method="GET",route="/requests",status="200"}', m)
        self.assertIn("llm_calls_total", m)
        self.assertIn("mcp_calls_total", m)

    def test_bad_cloud_and_auth(self):
        self.assertEqual(c.post("/requests", json={"title": "x", "cloud": "gcp"}).status_code, 422)
        os.environ["API_KEY"] = "k"
        try:
            self.assertEqual(c.get("/requests").status_code, 401)
            self.assertEqual(c.get("/requests", headers={"X-API-Key": "k"}).status_code, 200)
        finally:
            os.environ.pop("API_KEY")


if __name__ == "__main__":
    unittest.main()
