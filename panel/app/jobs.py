from __future__ import annotations

import asyncio
import logging
import traceback
from typing import Any, Awaitable, Callable

from .db import Database, utcnow
from .sshclient import SSHError

log = logging.getLogger("jojonet_panel.jobs")


class StepFailed(Exception):
    """Expected failure with a Persian message for the user."""


class Job:
    def __init__(self, manager: "JobManager", job_id: int, step_names: list[str]):
        self.manager = manager
        self.id = job_id
        self.steps: list[dict[str, Any]] = [{"name": n, "status": "pending", "detail": ""} for n in step_names]
        self._current = -1

    async def log(self, line: str) -> None:
        line = line.rstrip("\n")
        self.manager.buffer_log(self.id, line + "\n")
        await self.manager.publish(self.id, "log", {"line": line})

    async def step(self, index: int, status: str = "running", detail: str = "") -> None:
        if index >= len(self.steps):
            return
        if status == "running":
            self._current = index
        self.steps[index]["status"] = status
        if detail:
            self.steps[index]["detail"] = detail[:500]
        self.manager.db.update("jobs", self.id, {"steps": self.steps})
        await self.manager.publish(self.id, "step", {"index": index, **self.steps[index]})

    async def start(self, index: int, detail: str = "") -> None:
        await self.step(index, "running", detail)
        await self.log(f"▶ {self.steps[index]['name']}")

    async def ok(self, index: int, detail: str = "") -> None:
        await self.step(index, "ok", detail)

    async def fail_current(self, detail: str) -> None:
        if 0 <= self._current < len(self.steps) and self.steps[self._current]["status"] == "running":
            await self.step(self._current, "failed", detail)
        for s in self.steps:
            if s["status"] == "pending":
                s["status"] = "skipped"
        self.manager.db.update("jobs", self.id, {"steps": self.steps})


JobFunc = Callable[[Job], Awaitable[None]]

LOG_FLUSH_DELAY = 0.5
LOG_FLUSH_LINES = 200


class JobManager:
    def __init__(self, db: Database):
        self.db = db
        self._subs: dict[int, set[asyncio.Queue]] = {}
        self._tasks: set[asyncio.Task] = set()
        self._locks: dict[int, asyncio.Lock] = {}
        self._pending: dict[int, list[str]] = {}
        self._flush_timers: dict[int, asyncio.TimerHandle] = {}

    # Writing every line rewrote the growing log column and blocked the event loop during chatty installs.
    def buffer_log(self, job_id: int, text: str) -> None:
        buf = self._pending.setdefault(job_id, [])
        buf.append(text)
        if len(buf) >= LOG_FLUSH_LINES:
            self.flush_log(job_id)
        elif job_id not in self._flush_timers:
            self._flush_timers[job_id] = asyncio.get_running_loop().call_later(LOG_FLUSH_DELAY, self.flush_log, job_id)

    def flush_log(self, job_id: int) -> None:
        timer = self._flush_timers.pop(job_id, None)
        if timer is not None:
            timer.cancel()
        buf = self._pending.pop(job_id, None)
        if buf:
            self.db.append_log(job_id, "".join(buf))

    def flush_all(self) -> None:
        for job_id in list(self._pending):
            self.flush_log(job_id)

    def server_lock(self, server_id: int) -> asyncio.Lock:
        lock = self._locks.get(server_id)
        if lock is None:
            lock = self._locks[server_id] = asyncio.Lock()
        return lock

    def create(
        self,
        kind: str,
        title: str,
        steps: list[str],
        func: JobFunc,
        server_id: int | None = None,
        tunnel_id: int | None = None,
        owner_id: int | None = None,
        on_finish: Callable[[bool], Awaitable[None] | None] | None = None,
    ) -> int:
        job_id = self.db.insert(
            "jobs",
            {
                "kind": kind,
                "title": title,
                "status": "queued",
                "steps": [{"name": n, "status": "pending", "detail": ""} for n in steps],
                "log": "",
                "server_id": server_id,
                "tunnel_id": tunnel_id,
                "owner_id": owner_id,
                "created_at": utcnow(),
            },
        )
        job = Job(self, job_id, steps)
        task = asyncio.get_running_loop().create_task(self._run(job, func, on_finish))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job_id

    async def _run(self, job: Job, func: JobFunc, on_finish) -> None:  # noqa: ANN001
        self.db.update("jobs", job.id, {"status": "running"})
        ok = False
        try:
            await func(job)
            ok = True
        except (StepFailed, SSHError) as exc:
            await job.log(f"✖ {exc}")
            await job.fail_current(str(exc))
        except asyncio.CancelledError:
            await job.log("✖ کار لغو شد")
            await job.fail_current("لغو شد")
            raise
        except Exception as exc:  # pragma: no cover - defensive
            log.error("job %s crashed: %s", job.id, traceback.format_exc())
            await job.log(f"✖ خطای داخلی: {type(exc).__name__}: {exc}")
            await job.fail_current("خطای داخلی")
        finally:
            status = "ok" if ok else "failed"
            self.flush_log(job.id)
            self.db.update("jobs", job.id, {"status": status, "finished_at": utcnow()})
            if on_finish is not None:
                try:
                    res = on_finish(ok)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:  # pragma: no cover - defensive
                    log.error("on_finish for job %s failed: %s", job.id, traceback.format_exc())
            await self.publish(job.id, "done", {"status": status})

    def get(self, job_id: int) -> dict[str, Any] | None:
        self.flush_log(job_id)
        return self.db.one("SELECT * FROM jobs WHERE id=?", (job_id,))

    def list(self, limit: int = 50, owner_id: int | None = None) -> list[dict[str, Any]]:
        sql = (
            "SELECT id, kind, title, status, server_id, tunnel_id, owner_id, created_at, finished_at "
            "FROM jobs"
        )
        if owner_id is None:
            return self.db.all(sql + " ORDER BY id DESC LIMIT ?", (limit,))
        return self.db.all(sql + " WHERE owner_id=? ORDER BY id DESC LIMIT ?", (owner_id, limit))

    def subscribe(self, job_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._subs.setdefault(job_id, set()).add(q)
        return q

    def unsubscribe(self, job_id: int, q: asyncio.Queue) -> None:
        subs = self._subs.get(job_id)
        if subs is not None:
            subs.discard(q)
            if not subs:
                self._subs.pop(job_id, None)

    async def publish(self, job_id: int, event: str, data: dict[str, Any]) -> None:
        for q in list(self._subs.get(job_id, ())):
            try:
                q.put_nowait((event, data))
            except asyncio.QueueFull:
                pass

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self.flush_all()
