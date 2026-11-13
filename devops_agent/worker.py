"""Temporal worker: `python -m devops_agent.worker` (needs TEMPORAL_ADDRESS)."""
import asyncio
from concurrent.futures import ThreadPoolExecutor

from temporalio.worker import Worker

from . import activities, workflows as w


async def main():
    client = await w.connect()
    async with Worker(
        client, task_queue=w.TASK_QUEUE, workflows=[w.RequestWorkflow],
        activities=activities.ALL, activity_executor=ThreadPoolExecutor(8),
    ):
        await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
