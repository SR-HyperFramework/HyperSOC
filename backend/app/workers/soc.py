"""Run with python -m app.workers.soc. PostgreSQL is the durable job queue."""
import asyncio
import logging
import signal
from contextlib import suppress

from app.core.config import settings
from app.core.database import async_session_factory
from app.core.logging import configure_logging
from app.services.workflow import SOCWorkflow


async def run():
    settings.validate_runtime_settings()
    configure_logging()
    if not settings.automation_enabled:
        logging.getLogger(__name__).info("SOC automation is disabled")
        return
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    workflow = SOCWorkflow()

    async def keep_lease(job_id, token):
        while True:
            await asyncio.sleep(max(1, settings.automation_lease_seconds // 3))
            async with async_session_factory() as lease_db:
                if not await workflow.renew(lease_db, job_id, token):
                    return

    while not stop.is_set():
        try:
            async with async_session_factory() as db:
                job = await workflow.claim(db)
                if job is not None:
                    lease = asyncio.create_task(keep_lease(job.id, job.lease_token))
                    try:
                        await workflow.process(db, job)
                    finally:
                        lease.cancel()
                        with suppress(asyncio.CancelledError):
                            await lease
                    continue
        except Exception as exc:
            logging.getLogger(__name__).error("SOC worker iteration failed (%s)", type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.automation_poll_seconds)
        except asyncio.TimeoutError:
            pass


if __name__ == "__main__":
    asyncio.run(run())
