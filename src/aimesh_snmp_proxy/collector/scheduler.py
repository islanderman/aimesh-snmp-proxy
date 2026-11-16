"""Run collector jobs on a jittered cadence (design section 3).

A job runs at most once at a time: a tick that finds the previous run still
going is skipped, never queued. Each interval stretches or shrinks by up to
10 %, so many node polls do not lock into step, and the gap between two runs
stays within ``interval * (1 +/- jitter)``.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from aimesh_snmp_proxy.collector.backoff import Clock

_LOG = logging.getLogger(__name__)

JITTER = 0.10
DRAIN_S = 5.0
IDLE_WAKE_S = 60.0


@dataclass(eq=False)
class Job:
    name: str
    interval_s: float
    run: Callable[[], Awaitable[None]]
    due: float
    task: asyncio.Task[None] | None = None
    runs: int = 0
    skipped: int = 0


class Scheduler:
    """One loop that starts due jobs as tasks and sleeps until the next is due."""

    def __init__(
        self,
        *,
        clock: Clock,
        rng: random.Random | None = None,
        jitter: float = JITTER,
        drain_s: float = DRAIN_S,
    ) -> None:
        self._clock = clock
        self._rng = rng if rng is not None else random.SystemRandom()
        self._jitter = jitter
        self._drain_s = drain_s
        self._jobs: dict[str, Job] = {}
        self._running: set[asyncio.Task[None]] = set()
        self._wake = asyncio.Event()

    @staticmethod
    def offsets(interval_s: float, count: int) -> list[float]:
        """Node offsets ``i * interval / N`` that spread N jobs over one interval."""
        return [i * interval_s / count for i in range(count)]

    def add(
        self,
        name: str,
        interval_s: float,
        run: Callable[[], Awaitable[None]],
        *,
        offset_s: float = 0.0,
    ) -> Job:
        """Schedule ``run`` every ``interval_s``, first after ``offset_s``."""
        job = self._jobs.get(name)
        if job is None:
            job = Job(name, interval_s, run, due=self._clock.monotonic() + offset_s)
            self._jobs[name] = job
            self._wake.set()
        return job

    def remove(self, name: str) -> None:
        """Stop scheduling a job; a run in progress finishes on its own."""
        self._jobs.pop(name, None)

    def has(self, name: str) -> bool:
        return name in self._jobs

    def job(self, name: str) -> Job:
        return self._jobs[name]

    def names(self) -> list[str]:
        return sorted(self._jobs)

    async def run(self, stop: asyncio.Event) -> None:
        """Run until ``stop`` is set, then drain the jobs still running."""
        try:
            while not stop.is_set():
                now = self._clock.monotonic()
                for job in list(self._jobs.values()):
                    if job.due <= now:
                        self._start(job)
                        stretch = 1 + self._rng.uniform(-self._jitter, self._jitter)
                        job.due = max(job.due, now) + job.interval_s * stretch
                upcoming = min(
                    (job.due for job in self._jobs.values()), default=now + IDLE_WAKE_S
                )
                self._wake.clear()
                await self._sleep(stop, max(0.0, upcoming - self._clock.monotonic()))
        finally:
            await self._drain()

    def _start(self, job: Job) -> None:
        if job.task is not None and not job.task.done():
            job.skipped += 1
            _LOG.debug("job %s still running; tick skipped", job.name)
            return
        job.task = asyncio.create_task(self._execute(job), name=f"collector:{job.name}")
        self._running.add(job.task)
        job.task.add_done_callback(self._running.discard)

    async def _execute(self, job: Job) -> None:
        try:
            await job.run()
        except Exception as exc:  # a bug in one job must not stop the others
            # The type only: a message may quote a router reply (security logging)
            _LOG.error("job %s failed: %s", job.name, type(exc).__name__)
        finally:
            job.runs += 1

    async def _sleep(self, stop: asyncio.Event, delay: float) -> None:
        waiters = [
            asyncio.ensure_future(self._clock.sleep(delay)),
            asyncio.ensure_future(stop.wait()),
            asyncio.ensure_future(self._wake.wait()),
        ]
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiters:
                waiter.cancel()
            await asyncio.gather(*waiters, return_exceptions=True)

    async def _drain(self) -> None:
        pending = {task for task in self._running if not task.done()}
        if not pending:
            return
        _, stuck = await asyncio.wait(pending, timeout=self._drain_s)
        for task in stuck:
            task.cancel()
        await asyncio.gather(*stuck, return_exceptions=True)
