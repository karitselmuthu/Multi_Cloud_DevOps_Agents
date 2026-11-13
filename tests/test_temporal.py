"""Needs a Temporal server: `temporal server start-dev` then TEMPORAL_ADDRESS=localhost:7233. Skipped otherwise.
Runs the two real worker roles (agents + executor) against it."""
import asyncio
import os
import unittest
from concurrent.futures import ThreadPoolExecutor

ADDR = os.getenv("TEST_TEMPORAL_ADDRESS")  # set by tests/__init__ from TEMPORAL_ADDRESS
ALICE, BOB, CAROL = ({"X-API-Key": k} for k in ("ka", "kb", "kc"))


@unittest.skipUnless(ADDR, "TEMPORAL_ADDRESS not set")
class TemporalFlow(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        os.environ["TEMPORAL_ADDRESS"] = ADDR
        from fastapi.testclient import TestClient
        from temporalio.worker import Worker

        from devops_agent import activities, workflows as w
        from devops_agent.main import app

        self.c = TestClient(app)
        client = await w.connect()
        self.workers = [
            Worker(client, task_queue=w.AGENTS_QUEUE, workflows=[w.RequestWorkflow], activities=activities.AGENT, activity_executor=ThreadPoolExecutor(4)),
            Worker(client, task_queue=w.EXEC_QUEUE, activities=activities.EXEC, activity_executor=ThreadPoolExecutor(2)),
        ]
        self.tasks = [asyncio.create_task(x.run()) for x in self.workers]

    async def asyncTearDown(self):
        os.environ.pop("TEMPORAL_ADDRESS", None)
        for x in self.workers:
            await x.shutdown()
        await asyncio.gather(*self.tasks)

    def _req(self, method, path, headers, **kw):  # TestClient blocks; run it off-loop so the workers keep running
        return asyncio.to_thread(getattr(self.c, method), path, headers=headers, **kw)

    async def _status(self, rid, want):
        for _ in range(150):
            s = (await self._req("get", f"/requests/{rid}", BOB)).json()["status"]
            if s == want:
                return s
            await asyncio.sleep(0.1)
        return s

    async def test_approve_flow_with_token_and_separation_of_duties(self):
        rid = (await self._req("post", "/requests", CAROL, json={"title": "Logs bucket", "cloud": "aws"})).json()["id"]
        self.assertEqual(await self._status(rid, "pending_approval"), "pending_approval")
        self.assertEqual((await self._req("post", f"/requests/{rid}/approve", CAROL)).status_code, 403)  # own request
        self.assertEqual((await self._req("post", f"/requests/{rid}/approve", BOB)).json(), {"signalled": "approve"})
        self.assertEqual(await self._status(rid, "applied"), "applied")
        log = (await self._req("get", "/audit", BOB)).json()
        self.assertTrue(any(a["event"] == "mcp.call" and a["request_id"] == rid and "approver=bob" in a["detail"] for a in log))

    async def test_reject_flow(self):
        rid = (await self._req("post", "/requests", ALICE, json={"title": "Web", "cloud": "aws", "kind": "kubernetes"})).json()["id"]
        await self._status(rid, "pending_approval")
        self.assertEqual((await self._req("post", f"/requests/{rid}/reject", ALICE)).status_code, 200)
        self.assertEqual(await self._status(rid, "rejected"), "rejected")
        self.assertEqual((await self._req("post", f"/requests/{rid}/approve", BOB)).status_code, 409)


if __name__ == "__main__":
    unittest.main()
