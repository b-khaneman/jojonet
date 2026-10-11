from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from .sshclient import RemoteSession, SSHError

IDLE_SEC = 20 * 60
MAX_COLS = 300
MAX_ROWS = 120


def _size(raw: Any, default: int, lo: int, hi: int) -> int:
    try:
        n = int(raw)
    except (TypeError, ValueError):
        n = default
    return max(lo, min(n, hi))


async def pump_terminal(ws: WebSocket, sess: RemoteSession) -> None:
    proc = sess.proc
    if proc is None:
        await ws.send_json({"t": "e", "m": "شل باز نشد"})
        return

    stop = asyncio.Event()

    async def out_loop() -> None:
        try:
            while not stop.is_set():
                data = await proc.stdout.read(4096)
                if not data:
                    break
                text = data.decode("utf-8", "replace")
                if text:
                    await ws.send_json({"t": "o", "d": text})
        except (WebSocketDisconnect, ConnectionError, asyncio.CancelledError):
            pass
        except Exception:
            pass
        finally:
            stop.set()

    async def in_loop() -> None:
        try:
            while not stop.is_set():
                try:
                    raw = await asyncio.wait_for(ws.receive_text(), timeout=IDLE_SEC)
                except asyncio.TimeoutError:
                    await ws.send_json({"t": "e", "m": "اتصال به‌خاطر بی‌فعالیتی بسته شد"})
                    break
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                kind = msg.get("t")
                if kind == "i":
                    chunk = msg.get("d")
                    if isinstance(chunk, str) and chunk:
                        proc.stdin.write(chunk.encode("utf-8", "replace"))
                        await proc.stdin.drain()
                elif kind == "r":
                    sess.resize_shell(_size(msg.get("c"), 80, 20, MAX_COLS), _size(msg.get("r"), 24, 8, MAX_ROWS))
                elif kind == "x":
                    break
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            stop.set()

    out_task = asyncio.create_task(out_loop())
    in_task = asyncio.create_task(in_loop())
    try:
        await stop.wait()
    finally:
        out_task.cancel()
        in_task.cancel()
        await asyncio.gather(out_task, in_task, return_exceptions=True)


async def run_web_shell(ws: WebSocket, creds, cols: int, rows: int, label: str) -> None:
    session = RemoteSession(creds, connect_timeout=20)
    try:
        await session.connect_plain()
        await session.start_shell(cols, rows)
        await ws.send_json({"t": "s", "s": "ready", "n": label})
        await pump_terminal(ws, session)
    except SSHError as exc:
        await ws.send_json({"t": "e", "m": str(exc)})
    except Exception as exc:
        await ws.send_json({"t": "e", "m": f"اتصال ترمینال قطع شد: {exc}"})
    finally:
        await session.close()
        try:
            await ws.send_json({"t": "s", "s": "closed"})
        except Exception:
            pass
