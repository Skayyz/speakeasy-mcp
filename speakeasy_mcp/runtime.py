"""Parent-side process management: one-shot runs, interactive sessions, and the run store."""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import threading
import time
import uuid
from typing import Any

from . import worker

_CTX = mp.get_context("spawn")
STOP_GRACE_SECONDS = 20.0


def data_dir() -> str:
    d = os.environ.get("SPEAKEASY_MCP_DATA") or os.path.join(os.path.expanduser("~"), ".cache", "speakeasy-mcp")
    os.makedirs(os.path.join(d, "runs"), exist_ok=True)
    return d


def check_input_path(path: str) -> str:
    """Resolve an input path and enforce SPEAKEASY_MCP_ALLOWED_ROOTS when it is set."""
    real = os.path.realpath(os.path.expanduser(path))
    if not os.path.isfile(real):
        raise ValueError(f"input file not found: {path}")
    roots = [r for r in (os.environ.get("SPEAKEASY_MCP_ALLOWED_ROOTS") or "").split(os.pathsep) if r]
    if roots and not any(real == os.path.realpath(r) or real.startswith(os.path.realpath(r) + os.sep) for r in roots):
        raise ValueError(f"{path} is outside SPEAKEASY_MCP_ALLOWED_ROOTS")
    return real


def check_output_dir(path: str | None, run_dir: str) -> str:
    """Output goes under the run directory unless the caller names an allowed place."""
    if not path:
        return os.path.join(run_dir, "exports")
    real = os.path.realpath(os.path.expanduser(path))
    roots = [r for r in (os.environ.get("SPEAKEASY_MCP_ALLOWED_ROOTS") or "").split(os.pathsep) if r]
    roots.append(data_dir())
    if not any(real == os.path.realpath(r) or real.startswith(os.path.realpath(r) + os.sep) for r in roots):
        raise ValueError(f"{path} is outside the data dir and SPEAKEASY_MCP_ALLOWED_ROOTS")
    return real


# ---------------------------------------------------------------------------------------
# Run store
# ---------------------------------------------------------------------------------------


class RunStore:
    """Reports on disk, with a small in-memory cache of parsed JSON."""

    def __init__(self) -> None:
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    def new_run_dir(self) -> tuple[str, str]:
        run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        path = os.path.join(data_dir(), "runs", run_id)
        os.makedirs(path, exist_ok=True)
        return run_id, path

    def run_dir(self, run_id: str) -> str:
        if not run_id or any(c in run_id for c in "/\\") or run_id.startswith("."):
            raise ValueError(f"bad run_id {run_id!r}")
        path = os.path.join(data_dir(), "runs", run_id)
        if not os.path.isdir(path):
            raise ValueError(f"unknown run_id {run_id!r}; call list_runs")
        return path

    def save_meta(self, run_id: str, meta: dict) -> None:
        with open(os.path.join(self.run_dir(run_id), "meta.json"), "w") as f:
            json.dump(meta, f, indent=2, default=str)

    def meta(self, run_id: str) -> dict:
        p = os.path.join(self.run_dir(run_id), "meta.json")
        if not os.path.exists(p):
            return {}
        with open(p) as f:
            return json.load(f)

    def report(self, run_id: str) -> dict:
        with self._lock:
            if run_id in self._cache:
                return self._cache[run_id]
        p = os.path.join(self.run_dir(run_id), "report.json")
        if not os.path.exists(p):
            raise ValueError(f"run {run_id} has no report (the emulation failed before it wrote one)")
        with open(p) as f:
            rep = json.load(f)
        with self._lock:
            if len(self._cache) > 8:
                self._cache.pop(next(iter(self._cache)))
            self._cache[run_id] = rep
        return rep

    def list(self, limit: int = 50) -> list[dict]:
        root = os.path.join(data_dir(), "runs")
        out = []
        for name in sorted(os.listdir(root), reverse=True)[:limit]:
            try:
                m = self.meta(name)
            except ValueError:
                continue
            out.append(
                {
                    "run_id": name,
                    "input": m.get("input_path"),
                    "kind": m.get("kind"),
                    "status": m.get("status"),
                    "has_report": os.path.exists(os.path.join(root, name, "report.json")),
                }
            )
        return out


# ---------------------------------------------------------------------------------------
# One-shot emulation
# ---------------------------------------------------------------------------------------


def run_oneshot(job: dict, timeout_s: float) -> dict:
    parent, child = _CTX.Pipe(duplex=False)
    stop = _CTX.Event()
    proc = _CTX.Process(target=worker.oneshot_main, args=(job, child, stop), daemon=True)
    started = time.monotonic()
    proc.start()
    child.close()
    status = "completed"
    reply: dict[str, Any] | None = None
    if parent.poll(timeout_s):
        reply = _recv(parent)
    else:
        status = "stopped_at_timeout"
        stop.set()
        if parent.poll(STOP_GRACE_SECONDS):
            reply = _recv(parent)
        else:
            status = "killed_at_timeout"
    proc.join(5)
    if proc.is_alive():
        proc.kill()
        proc.join(5)
    if reply is None:
        reply = {"ok": False, "error": f"worker produced no result (exit code {proc.exitcode})"}
        if status == "completed":
            status = "crashed"
    reply["status"] = status if reply.get("ok") or status != "completed" else "failed"
    reply["wall_seconds"] = round(time.monotonic() - started, 2)
    return reply


def _recv(conn: Any) -> dict | None:
    try:
        return conn.recv()
    except (EOFError, OSError):
        return None


# ---------------------------------------------------------------------------------------
# Interactive sessions
# ---------------------------------------------------------------------------------------


class Session:
    def __init__(self, session_id: str, job: dict, op_timeout: float):
        self.id = session_id
        self.job = job
        self.op_timeout = op_timeout
        self.lock = threading.Lock()
        self.conn, child = _CTX.Pipe(duplex=True)
        self.stop = _CTX.Event()
        self.proc = _CTX.Process(target=worker.session_main, args=(job, child, self.stop), daemon=True)
        self.proc.start()
        child.close()
        self.dead = False
        self.created = time.time()
        reply = self._wait(op_timeout)
        if not reply.get("ok"):
            self.kill()
            raise RuntimeError(reply.get("error") or "session failed to start")
        self.info = reply["value"]

    def _wait(self, timeout: float) -> dict:
        if self.conn.poll(timeout):
            r = _recv(self.conn)
            if r is not None:
                return r
            self.dead = True
            return {"ok": False, "error": f"session worker exited (code {self.proc.exitcode})"}
        # Ask Speakeasy to stop the current run; it returns control to the op.
        self.stop.set()
        if self.conn.poll(STOP_GRACE_SECONDS):
            r = _recv(self.conn)
            if r is not None:
                r.setdefault("note", "op hit the timeout; emulation was stopped via exit_event")
                return r
        self.kill()
        return {"ok": False, "error": f"op exceeded {timeout}s and the worker was killed; session closed"}

    def call(self, op: str, timeout: float | None = None, **args: Any) -> Any:
        with self.lock:
            if self.dead:
                raise RuntimeError(f"session {self.id} is closed")
            try:
                self.conn.send({"op": op, "args": args})
            except (BrokenPipeError, OSError):
                self.dead = True
                raise RuntimeError(f"session {self.id} worker is gone") from None
            reply = self._wait(timeout or self.op_timeout)
        if not reply.get("ok"):
            raise RuntimeError(reply.get("error", "unknown error"))
        value = reply["value"]
        if reply.get("note") and isinstance(value, dict):
            value["note"] = reply["note"]
        return value

    def close(self) -> None:
        if not self.dead:
            try:
                self.call("close", timeout=10)
            except RuntimeError:
                pass
        self.kill()

    def kill(self) -> None:
        self.dead = True
        if self.proc.is_alive():
            self.proc.kill()
        self.proc.join(5)


class SessionManager:
    def __init__(self, max_sessions: int = 4):
        self.max_sessions = max_sessions
        self.sessions: dict[str, Session] = {}
        self.lock = threading.Lock()

    def open(self, job: dict, op_timeout: float) -> Session:
        with self.lock:
            for sid in [s for s, v in self.sessions.items() if v.dead]:
                self.sessions.pop(sid)
            if len(self.sessions) >= self.max_sessions:
                raise RuntimeError(f"too many open sessions ({self.max_sessions}); close one first")
        sid = "s-" + uuid.uuid4().hex[:8]
        sess = Session(sid, job, op_timeout)
        with self.lock:
            self.sessions[sid] = sess
        return sess

    def get(self, sid: str) -> Session:
        s = self.sessions.get(sid)
        if s is None or s.dead:
            raise ValueError(f"no open session {sid!r}")
        return s

    def close(self, sid: str) -> None:
        s = self.sessions.pop(sid, None)
        if s is None:
            raise ValueError(f"no open session {sid!r}")
        s.close()

    def close_all(self) -> None:
        for sid in list(self.sessions):
            try:
                self.close(sid)
            except Exception:  # noqa: BLE001
                pass
