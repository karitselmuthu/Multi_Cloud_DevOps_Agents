"""Durable request lifecycle on Temporal: pipeline (agents queue) -> plan (executor queue) -> wait for a human decision
(signal carrying the approval token) -> apply (executor queue, never auto-retried).
Enabled when TEMPORAL_ADDRESS is set; otherwise main.py runs the pipeline in-process (dry-run only, no real execution).
No app imports here: the Temporal sandbox re-imports this module, so activities are referenced by name."""
import asyncio
import os
from dataclasses import dataclass
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

AGENTS_QUEUE = "devops-agent-agents"  # LLM-facing worker: no cloud creds, no approval secret
EXEC_QUEUE = "devops-agent-exec"  # executor: cloud role + approval secret, no LLM keys
TASK_QUEUE = AGENTS_QUEUE


@dataclass
class Decision:
    approved: bool
    token: str = ""


@workflow.defn
class RequestWorkflow:
    def __init__(self):
        self.decision = None

    @workflow.signal
    def decide(self, d: Decision):
        self.decision = d

    @workflow.run
    async def run(self, rid: int) -> str:
        retry3 = RetryPolicy(maximum_attempts=3)
        status = await workflow.execute_activity("run_pipeline", rid, start_to_close_timeout=timedelta(minutes=10), retry_policy=retry3)
        if status == "planning":
            status = await workflow.execute_activity(
                "plan", rid, task_queue=EXEC_QUEUE, start_to_close_timeout=timedelta(minutes=15), retry_policy=retry3
            )
        if status != "pending_approval":  # blocked/failed: nothing to approve
            return status
        try:
            await workflow.wait_condition(lambda: self.decision is not None, timeout=timedelta(days=7))
        except asyncio.TimeoutError:
            return await workflow.execute_activity("expire", rid, start_to_close_timeout=timedelta(minutes=1))
        if not self.decision.approved:
            return "rejected"
        # never auto-retry an apply: a half-applied infra change must be looked at by a human
        return await workflow.execute_activity(
            "apply", args=[rid, self.decision.token], task_queue=EXEC_QUEUE,
            start_to_close_timeout=timedelta(minutes=30), retry_policy=RetryPolicy(maximum_attempts=1),
        )


async def connect():
    from temporalio.client import Client

    return await Client.connect(os.environ["TEMPORAL_ADDRESS"], namespace=os.getenv("TEMPORAL_NAMESPACE", "default"))
