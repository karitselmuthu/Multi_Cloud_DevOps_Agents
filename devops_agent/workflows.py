"""Durable request lifecycle on Temporal: pipeline -> wait for human decision (signal) -> apply.
Enabled when TEMPORAL_ADDRESS is set; otherwise main.py runs the same steps in-process."""
import asyncio
import os
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

TASK_QUEUE = "devops-agent"


@workflow.defn
class RequestWorkflow:
    def __init__(self):
        self.decision = None

    @workflow.signal
    def decide(self, approved: bool):
        self.decision = approved

    @workflow.run
    async def run(self, rid: int) -> str:
        status = await workflow.execute_activity(
            "run_pipeline", rid, start_to_close_timeout=timedelta(minutes=10), retry_policy=RetryPolicy(maximum_attempts=3)
        )
        if status != "pending_approval":  # blocked/failed: nothing to approve
            return status
        try:
            await workflow.wait_condition(lambda: self.decision is not None, timeout=timedelta(days=7))
        except asyncio.TimeoutError:
            return await workflow.execute_activity("expire", rid, start_to_close_timeout=timedelta(minutes=1))
        if not self.decision:
            return "rejected"
        # never auto-retry an apply: a half-applied infra change must be looked at by a human
        return await workflow.execute_activity(
            "apply", rid, start_to_close_timeout=timedelta(minutes=30), retry_policy=RetryPolicy(maximum_attempts=1)
        )


async def connect():
    from temporalio.client import Client

    return await Client.connect(os.environ["TEMPORAL_ADDRESS"], namespace=os.getenv("TEMPORAL_NAMESPACE", "default"))
