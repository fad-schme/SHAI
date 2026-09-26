"""run_sync — the one bridge from a sync caller to the async boundaries."""
from __future__ import annotations

import asyncio
import contextvars
import gc
import threading
import time
import warnings

import pytest

from harness.integrations import base
from harness.integrations.base import run_sync, shai_tool

_var: contextvars.ContextVar[str] = contextvars.ContextVar("bridge_var", default="unset")


async def _read_var() -> str:
    return _var.get()


def test_concurrent_callers_each_get_their_own_result():
    results: dict[int, int] = {}

    async def work(i: int) -> int:
        await asyncio.sleep(0.01)
        return i * 2

    def call(i: int) -> None:
        results[i] = run_sync(work(i))

    threads = [threading.Thread(target=call, args=(i,)) for i in range(32)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + 30
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))

    assert not any(t.is_alive() for t in threads)
    assert results == {i: i * 2 for i in range(32)}


def test_caller_context_reaches_the_coroutine_from_a_plain_thread():
    token = _var.set("caller")
    try:
        assert run_sync(_read_var()) == "caller"
    finally:
        _var.reset(token)


def test_caller_context_reaches_the_coroutine_when_the_caller_has_a_running_loop():
    async def inside() -> str:
        return run_sync(_read_var())

    token = _var.set("caller")
    try:
        assert asyncio.run(inside()) == "caller"
    finally:
        _var.reset(token)


def test_exception_reaches_the_caller_unchanged():
    async def boom() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        run_sync(boom())


def test_call_from_the_bridge_loop_itself_fails_instead_of_deadlocking():
    async def nested() -> None:
        run_sync(_read_var())

    with pytest.raises(RuntimeError, match="bridge loop"):
        run_sync(nested())


def _finishes(fn, seconds: float = 10.0) -> bool:
    """True when fn returns within `seconds`; a hang fails instead of stalling the suite."""
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    t.join(timeout=seconds)
    return not t.is_alive()


@pytest.mark.parametrize("exc", [SystemExit(3), KeyboardInterrupt()])
def test_base_exception_reaches_the_caller_and_the_bridge_survives(exc: BaseException):
    seen: list[object] = []

    def call() -> None:
        async def raise_it() -> None:
            raise exc

        try:
            run_sync(raise_it())
        except BaseException as e:  # noqa: BLE001 - the point of the test
            seen.append(e)
        seen.append(run_sync(_read_var()))

    assert _finishes(call), "run_sync hung after a BaseException in the coroutine"
    assert seen == [exc, "unset"]


def test_a_dead_bridge_thread_is_replaced():
    run_sync(_read_var())                       # make sure a bridge is running
    dead = base._bridge_loop
    dead.call_soon_threadsafe(dead.stop)
    base._bridge_thread.join(timeout=10)
    assert not base._bridge_thread.is_alive()

    out: list[str] = []
    assert _finishes(lambda: out.append(run_sync(_read_var())))
    assert out == ["unset"]


def test_a_sync_called_async_shai_tool_body_stays_off_the_bridge_thread():
    """The body is user code, not a boundary: a blocking one must not stall the bridge."""
    where: list[str] = []

    @shai_tool(tags=["read"])
    async def probe(query: str) -> str:
        """Record the thread the body runs on."""
        where.append(threading.current_thread().name)
        return "ok"

    assert probe(query="q") == "ok"
    assert probe.invoke({"query": "q"}) == "ok"
    assert "shai-sync-bridge" not in where and len(where) == 2


def test_the_bridge_loop_guard_leaves_no_unawaited_coroutine():
    async def leaf() -> int:
        return 1

    async def nested() -> None:
        with pytest.raises(RuntimeError, match="bridge loop"):
            run_sync(leaf())

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        run_sync(nested())
        gc.collect()

    assert [str(w.message) for w in caught if "never awaited" in str(w.message)] == []
