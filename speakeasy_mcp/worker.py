"""Code that runs in child processes.

Each emulation runs in its own ``spawn`` process. Unicorn can segfault, hang in native code,
or leak memory, and none of that should take the MCP server down with it. The parent sends a
stop event when the wall-clock budget runs out (Speakeasy checks ``exit_event`` and still
writes a report), and kills the child if it does not stop.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import traceback
from typing import Any

# Config keys that changed names between Speakeasy builds. The first name that the running
# build's default config has wins.
_ALIASES = {
    "max_api_calls": ("max_api_calls", "max_api_count"),
    "max_run_time": ("max_run_time", "timeout"),
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def build_config(options: dict | None, overrides: dict | None) -> dict:
    """Merge convenience options and raw overrides into the build's default config."""
    import speakeasy

    base = speakeasy.Speakeasy().config.model_dump(mode="json")
    opts = dict(options or {})
    flat: dict[str, Any] = {}
    for key in ("max_instructions", "max_total_time", "random_seed", "command_line", "stack_size"):
        if opts.get(key) is not None:
            flat[key] = opts[key]
    for key, names in _ALIASES.items():
        if opts.get(key) is not None:
            flat[next((n for n in names if n in base), key)] = opts[key]
    analysis = {}
    for key in ("coverage", "memory_tracing", "strings", "dynamic_code_snapshots"):
        if opts.get(key) is not None and key in (base.get("analysis") or {}):
            analysis[key] = opts[key]
    if analysis:
        flat["analysis"] = analysis
    for key in ("snapshot_memory_regions", "keep_memory_on_free"):
        if opts.get(key) is not None and key in base:
            flat[key] = opts[key]
    merged = _deep_merge(base, flat)
    if overrides:
        merged = _deep_merge(merged, overrides)
    return merged


def _quiet_logging() -> None:
    # Speakeasy logs every API at INFO; the MCP server speaks JSON-RPC on stdout, so keep
    # the child silent on stdout and mostly silent on stderr.
    logging.basicConfig(level=logging.WARNING)
    for name in ("speakeasy", "unicorn"):
        logging.getLogger(name).setLevel(logging.ERROR)


def _make_emulator(job: dict, stop_event: Any):
    import speakeasy

    cfg = build_config(job.get("options"), job.get("config_overrides"))
    kwargs: dict[str, Any] = {"config": cfg, "argv": job.get("argv") or [], "exit_event": stop_event}
    if job.get("volumes"):
        kwargs["volumes"] = job["volumes"]
    return speakeasy.Speakeasy(**kwargs)


def _load(se: Any, job: dict) -> dict:
    """Load the input and return a description of it."""
    if job["kind"] == "pe":
        module = se.load_module(path=job["path"], filename=job.get("guest_filename"))
        exports = [
            {"name": e.name, "ordinal": getattr(e, "ordinal", None), "address": hex(e.address)}
            for e in (module.get_exports() or [])
        ]
        info = {
            "kind": "pe",
            "module_type": getattr(module, "module_type", None),
            "base": hex(module.base),
            "image_size": getattr(module, "image_size", None),
            "entry_point": hex(module.base + module.ep) if getattr(module, "ep", None) is not None else None,
            "exports": exports,
            "emulator": type(se.emu).__name__,
        }
        return {"module": module, "info": info}
    addr = se.load_shellcode(fpath=job["path"], arch=job["arch"], filename=job.get("guest_filename"))
    return {"sc_addr": addr, "info": {"kind": "shellcode", "arch": job["arch"], "base": hex(addr)}}


def _run(se: Any, job: dict, loaded: dict) -> None:
    if job["kind"] == "pe":
        se.run_module(
            loaded["module"],
            all_entrypoints=bool(job.get("all_entrypoints")),
            emulate_children=bool(job.get("emulate_children")),
            entry_point=job.get("entry_point_rva"),
        )
    else:
        se.run_shellcode(loaded["sc_addr"], offset=int(job.get("offset") or 0))


def _write_outputs(se: Any, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "report.json")
    with open(report_path, "w") as f:
        f.write(se.get_json_report())
    result = {"report_path": report_path}
    try:
        if se.get_dropped_files():
            zpath = os.path.join(out_dir, "dropped_files.zip")
            with open(zpath, "wb") as f:
                f.write(se.create_file_archive())
            result["dropped_files_zip"] = zpath
    except Exception as err:  # noqa: BLE001 - the archive is best effort
        result["dropped_files_error"] = repr(err)
    return result


def oneshot_main(job: dict, conn: Any, stop_event: Any) -> None:
    """Child entry point: load, run, write report, reply once."""
    _quiet_logging()
    se = None
    reply: dict[str, Any] = {"ok": False}
    try:
        se = _make_emulator(job, stop_event)
        loaded = _load(se, job)
        reply["input"] = loaded["info"]
        try:
            _run(se, job, loaded)
        except Exception as err:  # noqa: BLE001 - keep the partial report
            reply["run_exception"] = _err_text(err)
        reply.update(_write_outputs(se, job["out_dir"]))
        reply["ok"] = True
    except Exception as err:  # noqa: BLE001
        reply["error"] = _err_text(err)
        reply["traceback"] = traceback.format_exc(limit=8)
    finally:
        try:
            conn.send(reply)
        finally:
            if se is not None:
                try:
                    se.shutdown()
                except Exception:  # noqa: BLE001
                    pass


# --------------------------------------------------------------------------------------
# Interactive sessions
# --------------------------------------------------------------------------------------


def _hexdump(data: bytes, base: int, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:016x}  {hexpart:<{width * 3}} {text}")
    return "\n".join(lines)


def _prot(p: Any) -> Any:
    """Speakeasy perms: read 0x02, write 0x04, exec 0x10."""
    if not isinstance(p, int):
        return p
    return ("r" if p & 0x02 else "-") + ("w" if p & 0x04 else "-") + ("x" if p & 0x10 else "-")


def _err_text(err: BaseException) -> str:
    """Exception text plus its cause, so a ConfigError shows the pydantic detail."""
    text = f"{type(err).__name__}: {err}"
    cause = err.__cause__
    if cause is not None:
        text += f" ({type(cause).__name__}: {str(cause).strip()[:1500]})"
    return text


class _Session:
    def __init__(self, job: dict, stop_event: Any):
        self.job = job
        self.stop_event = stop_event
        self.se = _make_emulator(job, stop_event)
        self.loaded = _load(self.se, job)
        self.api_hits: dict[str, list[str]] = {}
        self.hooks: list[Any] = []

    # Each op returns a JSON-able value.
    def op_info(self) -> dict:
        return self.loaded["info"]

    def op_run(self, all_entrypoints: bool = False, emulate_children: bool = False, entry_point_rva=None, offset=0):
        job = dict(self.job, all_entrypoints=all_entrypoints, emulate_children=emulate_children)
        job["entry_point_rva"] = entry_point_rva
        job["offset"] = offset
        _run(self.se, job, self.loaded)
        return {"done": True, "pc": hex(self.se.get_pc())}

    def _resolve(self, target: str | int) -> int:
        if isinstance(target, int):
            return target
        t = target.strip()
        if t.lower().startswith("0x") or t.isdigit():
            return int(t, 0)
        module = self.loaded.get("module")
        if module is not None:
            for e in module.get_exports() or []:
                if e.name == t:
                    return e.address
        for addr, sym in (self.se.get_symbols() or {}).items():
            name = sym if isinstance(sym, str) else ".".join(str(x) for x in sym)
            if name.lower() == t.lower() or name.lower().endswith("." + t.lower()):
                return addr
        raise ValueError(f"cannot resolve {target!r} to an address (not hex, export or symbol)")

    def op_call(self, target: str, args: list[int] | None = None) -> dict:
        addr = self._resolve(target)
        self.se.call(addr, list(args or []))
        regs = self.se.get_all_registers()
        ret = regs.get("rax", regs.get("eax"))
        return {"called": hex(addr), "return_register": ret}

    def op_read_memory(self, address: str | int, size: int = 256) -> str:
        addr = self._resolve(address)
        size = max(1, min(int(size), 65536))
        return _hexdump(self.se.mem_read(addr, size), addr)

    def op_dump_memory(self, address: str | int, size: int, out_path: str) -> dict:
        addr = self._resolve(address)
        data = self.se.mem_read(addr, int(size))
        with open(out_path, "wb") as f:
            f.write(data)
        return {"file": out_path, "size": len(data)}

    def op_read_string(self, address: str | int, width: int = 1, max_chars: int = 1024) -> str:
        return self.se.read_mem_string(self._resolve(address), width=width, max_chars=max_chars)

    def op_write_memory(self, address: str | int, hex_bytes: str) -> dict:
        addr = self._resolve(address)
        data = bytes.fromhex(hex_bytes.replace(" ", ""))
        self.se.mem_write(addr, data)
        return {"written": len(data), "address": hex(addr)}

    def op_registers(self) -> dict:
        return self.se.get_all_registers()

    def op_set_register(self, name: str, value: int) -> dict:
        self.se.reg_write(name, int(value))
        return {name: hex(self.se.reg_read(name))}

    def op_disasm(self, address: str | int, count: int = 20) -> list[str]:
        import capstone

        addr = self._resolve(address)
        mode = capstone.CS_MODE_64 if self.se.get_ptr_size() == 8 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        syms = self.se.get_symbols() or {}
        data = self.se.mem_read(addr, min(int(count) * 15, 4096))
        out = []
        for ins in md.disasm(data, addr):
            line = f"{ins.address:#x}: {ins.mnemonic} {ins.op_str}".rstrip()
            sym = syms.get(ins.address)
            if sym:
                line = f"<{'.'.join(sym) if isinstance(sym, tuple) else sym}>\n" + line
            if ins.mnemonic in ("call", "jmp"):
                tgt = self._branch_symbol(ins.op_str, syms)
                if tgt:
                    line += f"    ; {tgt}"
            out.append(line)
            if len(out) >= count:
                break
        return out

    def _branch_symbol(self, op: str, syms: dict) -> str | None:
        """Name the target of a direct call/jmp, or of an indirect one through a pointer (IAT)."""
        try:
            if op.startswith("0x"):
                tgt = int(op, 16)
            elif "ptr [0x" in op and op.endswith("]"):
                ptr = int(op[op.index("[") + 1 : -1], 16)
                tgt = int.from_bytes(self.se.mem_read(ptr, self.se.get_ptr_size()), "little")
            else:
                return None
        except Exception:  # noqa: BLE001 - unmapped pointer, etc.
            return None
        sym = syms.get(tgt)
        if sym is None:
            return None
        return ".".join(sym) if isinstance(sym, tuple) else str(sym)

    def op_memory_map(self, tag_filter: str | None = None, limit: int = 200) -> list[dict]:
        rows = []
        for mm in self.se.get_mem_maps():
            tag = str(getattr(mm, "tag", ""))
            if tag_filter and tag_filter.lower() not in tag.lower():
                continue
            rows.append({"base": hex(mm.base), "size": hex(mm.size), "tag": tag, "prot": _prot(getattr(mm, "prot", None))})
        return rows[:limit]

    def op_symbols(self, contains: str | None = None, limit: int = 200) -> list[str]:
        rows = []
        for addr, sym in sorted((self.se.get_symbols() or {}).items()):
            name = ".".join(sym) if isinstance(sym, tuple) else str(sym)
            if contains and contains.lower() not in name.lower():
                continue
            rows.append(f"{addr:#x} {name}")
            if len(rows) >= limit:
                break
        return rows

    def op_hook_api(self, module: str, api: str, return_value: int | None = None) -> dict:
        """Override (or just record) an API. With return_value None the real handler runs."""
        key = f"{module}.{api}"
        hits = self.api_hits.setdefault(key, [])

        def cb(emu, api_name, func, params):
            hits.append(f"{api_name}({', '.join(hex(p) if isinstance(p, int) else str(p) for p in params)})")
            if return_value is None:
                return func(params) if func else 0
            return return_value

        self.hooks.append(self.se.add_api_hook(cb, module, api))
        return {"hooked": key, "return_value": None if return_value is None else hex(return_value)}

    def op_api_hook_hits(self, pattern: str = "*", limit: int = 100) -> dict:
        return {k: v[-limit:] for k, v in self.api_hits.items() if fnmatch.fnmatch(k.lower(), pattern.lower())}

    def op_report(self, out_dir: str) -> dict:
        return _write_outputs(self.se, out_dir)

    def close(self) -> None:
        try:
            self.se.shutdown()
        except Exception:  # noqa: BLE001
            pass


def session_main(job: dict, conn: Any, stop_event: Any) -> None:
    """Child entry point for an interactive session: serve ops until 'close'."""
    _quiet_logging()
    try:
        sess = _Session(job, stop_event)
        conn.send({"ok": True, "value": sess.op_info()})
    except Exception as err:  # noqa: BLE001
        conn.send({"ok": False, "error": _err_text(err), "traceback": traceback.format_exc(limit=8)})
        return
    while True:
        try:
            msg = conn.recv()
        except EOFError:
            break
        op = msg.get("op")
        if op == "close":
            sess.close()
            conn.send({"ok": True, "value": "closed"})
            break
        stop_event.clear()
        fn = getattr(sess, f"op_{op}", None)
        if fn is None:
            conn.send({"ok": False, "error": f"unknown op {op}"})
            continue
        try:
            value = fn(**(msg.get("args") or {}))
            json.dumps(value, default=str)
            conn.send({"ok": True, "value": value})
        except Exception as err:  # noqa: BLE001
            conn.send({"ok": False, "error": _err_text(err), "traceback": traceback.format_exc(limit=6)})
