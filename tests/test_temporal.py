"""Needs a Temporal server: `temporal server start-dev` then TEMPORAL_ADDRESS=localhost:7233. Skipped otherwise."""
import asyncio
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

ADDR = os.getenv("TEMPORAL_ADDRESS")
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "tw.db")
os.environ.pop("API_KEY", None)
os.environ.pop("EXECUTE", None)


@unittest.skipUnless(ADDR, "TEMPORAL_ADDRESS not set")
class TemporalFlow(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from fastapi.testclient import TestClient
        from temporalio.worker import Worker

        from devops_agent import activities, workflows as w
        from devops_agent.main import app

        self.c = TestClient(app)
        self.worker = Worker(
            await w.connect(), task_queue=w.TASK_QUEUE, workflows=[w.RequestWorkflow],
            activities=activities.ALL, activity_executor=ThreadPoolExecutor(4),
        )
        self.run_task = asyncio.create_task(self.worker.run())

    async def asyncTearDown(self):
        await self.worker.shutdown()
        await self.run_task

    def _post(self, *a, **k):  # TestClient blocks; run it off-loop so the worker keeps running
        return asyncio.to_thread(self.c.post, *a, **k)

    async def _status(self, rid, want):
        for _ in range(100):
            s = (await asyncio.to_thread(self.c.get, f"/requests/{rid}")).json()["status"]
            if s == want:
                return s
            await asyncio.sleep(0.1)
        return s

    async def test_approve_flow(self):
        rid = (await self._post("/requests", json={"title": "Logs bucket", "cloud": "aws"})).json()["id"]
        self.assertEqual(await self._status(rid, "pending_approval"), "pending_approval")
        self.assertEqual((await self._post(f"/requests/{rid}/approve")).json(), {"signalled": "approve"})
        self.assertEqual(await self._status(rid, "applied"), "applied")

    async def test_reject_flow(self):
        rid = (await self._post("/requests", json={"title": "Web", "cloud": "aws", "kind": "kubernetes"})).json()["id"]
        await self._status(rid, "pending_approval")
        self.assertEqual((await self._post(f"/requests/{rid}/reject")).status_code, 200)
        self.assertEqual(await self._status(rid, "rejected"), "rejected")
        self.assertEqual((await self._post(f"/requests/{rid}/approve")).status_code, 409)


if __name__ == "__main__":
    unittest.main()
