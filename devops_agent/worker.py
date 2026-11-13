"""Temporal workers. Run ONE role per process so secrets stay separated:
  python -m devops_agent.worker agents    # workflows + LLM pipeline. Needs LLM keys. Never gets APPROVAL_SECRET or cloud creds.
  python -m devops_agent.worker executor  # plan/apply. Needs APPROVAL_SECRET + cloud role. Never gets LLM keys."""
import asyncio
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from temporalio.worker import Worker

from . import activities, workflows as w


async def main(role):
    os.environ["ROLE"] = role  # the gateway only executes for real when ROLE == "executor"
    client = await w.connect()
    if role == "agents":
        worker = Worker(client, task_queue=w.AGENTS_QUEUE, workflows=[w.RequestWorkflow], activities=activities.AGENT,
                        activity_executor=ThreadPoolExecutor(8))
    else:
        worker = Worker(client, task_queue=w.EXEC_QUEUE, activities=activities.EXEC, activity_executor=ThreadPoolExecutor(2))
    async with worker:
        await asyncio.Event().wait()


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("agents", "executor"):
        sys.exit("usage: python -m devops_agent.worker agents|executor")
    asyncio.run(main(sys.argv[1]))
