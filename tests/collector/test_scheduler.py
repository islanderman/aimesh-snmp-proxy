import asyncio
import itertools
import logging

import pytest

from aimesh_snmp_proxy.collector.scheduler import Scheduler


def run_until(clock, sched, until, *, hooks=()):
    """Run the scheduler until the fake clock reaches ``until``; return run times."""

    async def scenario():
        stop = asyncio.Event()
        task = asyncio.create_task(sched.run(stop))
        while clock.monotonic() < until:
            for hook in hooks:
                hook()
            await asyncio.sleep(0)
        stop.set()
        await task

    asyncio.run(scenario())


def recorder(clock, log):
    async def job():
        log.append(clock.monotonic())

    return job


def test_jobs_run_on_their_interval_with_upper_jitter(clock, rng_high):
    sched = Scheduler(clock=clock, rng=rng_high)
    times = []
    sched.add("metrics", 60, recorder(clock, times))
    start = clock.monotonic()
    run_until(clock, sched, start + 200)
    gaps = [b - a for a, b in itertools.pairwise(times)]
    assert times[0] == start
    assert gaps == pytest.approx([66, 66, 66][: len(gaps)])


def test_lower_jitter_bound_is_90_percent(clock, rng_low):
    sched = Scheduler(clock=clock, rng=rng_low)
    times = []
    sched.add("topology", 300, recorder(clock, times))
    run_until(clock, sched, clock.monotonic() + 600)
    assert times[1] - times[0] == pytest.approx(270)


def test_offset_delays_the_first_run(clock, rng_high):
    sched = Scheduler(clock=clock, rng=rng_high)
    times = []
    start = clock.monotonic()
    sched.add("metrics:b", 60, recorder(clock, times), offset_s=30)
    run_until(clock, sched, start + 31)
    assert times == [start + 30]


def test_a_running_job_is_never_started_twice(clock, rng_high):
    sched = Scheduler(clock=clock, rng=rng_high, drain_s=0.05)
    gate = asyncio.Event
    state = {"started": 0, "event": None}

    async def slow():
        state["started"] += 1
        await state["event"].wait()

    def make_event():
        if state["event"] is None:
            state["event"] = gate()

    sched.add("slow", 60, slow)
    run_until(clock, sched, clock.monotonic() + 600, hooks=[make_event])
    assert state["started"] == 1
    assert sched.job("slow").skipped >= 8


def test_failing_job_is_logged_without_its_message_and_keeps_running(
    clock, rng_high, caplog
):
    sched = Scheduler(clock=clock, rng=rng_high)
    calls = []

    async def broken():
        calls.append(1)
        raise ValueError("canary-router-Pa55-1")

    sched.add("broken", 60, broken)
    with caplog.at_level(logging.ERROR):
        run_until(clock, sched, clock.monotonic() + 130)
    assert len(calls) >= 2
    assert "canary" not in caplog.text
    assert "ValueError" in caplog.text


def test_jobs_can_be_added_and_removed_while_running(clock, rng_high):
    sched = Scheduler(clock=clock, rng=rng_high)
    times = []
    start = clock.monotonic()
    added = []

    def add_later():
        if not added and clock.monotonic() >= start + 100:
            added.append(True)
            sched.add("late", 60, recorder(clock, times))

    sched.add("tick", 10, recorder(clock, []))
    run_until(clock, sched, start + 140, hooks=[add_later])
    assert times
    assert times[0] >= start + 100
    sched.remove("late")
    assert not sched.has("late")
    sched.remove("never-added")


def test_stop_waits_for_running_jobs_then_cancels_stragglers(clock, rng_high):
    finished = []

    async def quick():
        await asyncio.sleep(0)
        finished.append("quick")

    async def stuck():
        await asyncio.Event().wait()

    async def scenario():
        sched = Scheduler(clock=clock, rng=rng_high, drain_s=0.05)
        sched.add("quick", 60, quick)
        sched.add("stuck", 60, stuck)
        stop = asyncio.Event()
        task = asyncio.create_task(sched.run(stop))
        for _ in range(5):
            await asyncio.sleep(0)
        stop.set()
        await asyncio.wait_for(task, timeout=2)
        return sched

    sched = asyncio.run(scenario())
    assert finished == ["quick"]
    assert sched.job("stuck").task.cancelled()


def test_node_offsets_spread_n_jobs_across_the_interval():
    assert Scheduler.offsets(60, 4) == [0, 15, 30, 45]
    assert Scheduler.offsets(300, 1) == [0]
    assert Scheduler.offsets(60, 0) == []
