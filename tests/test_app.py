import os
import tempfile
import unittest

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ.pop("API_KEY", None)
os.environ.pop("EXECUTE", None)

from fastapi.testclient import TestClient  # noqa: E402

from devops_agent import agents, mcp, rag  # noqa: E402
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
