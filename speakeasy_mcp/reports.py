"""Read Speakeasy JSON reports and answer questions about them.

Speakeasy has two report formats in the wild: 5.0.0 (the 2.0.0b9 wheel on PyPI) and
6.0.0 (the current master branch). They differ mostly in field names and in whether
machine words are ints or hex strings. ``normalize_entry`` and ``normalize_top`` map
both to one shape, so the query functions do not care which build wrote the report.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import os
import zlib
from collections import Counter
from typing import Any

# (6.0.0 name, 5.0.0 name)
_EP_FIELDS = {
    "type": ("type", "ep_type"),
    "name": ("name", "ep_name"),
    "start_address": ("start_address", "start_addr"),
    "args": ("args", "ep_args"),
    "instruction_count": ("instruction_count", "instr_count"),
    "return_value": ("return_value", "ret_val"),
    "api_hash": ("api_hash", "apihash"),
    "symbol_accesses": ("symbol_accesses", "sym_accesses"),
}
_TOP_FIELDS = {
    "file_type": ("file_type", "filetype"),
    "path": ("path", "filepath"),
}

# Event types that are interesting for triage (everything except api and raw memory traffic).
IOC_EVENT_TYPES = {
    "process_create",
    "thread_create",
    "thread_inject",
    "module_load",
    "file_create",
    "file_open",
    "file_write",
    "file_delete",
    "directory_create",
    "directory_delete",
    "reg_open_key",
    "reg_create_key",
    "reg_read_value",
    "reg_write_value",
    "reg_list_subkeys",
    "reg_delete_key",
    "reg_delete_value",
    "net_dns",
    "net_traffic",
    "net_http",
    "exception",
    "mem_protect",
}


# Event fields that hold machine words; other ints (sizes, counts, ids) stay decimal.
_WORD_KEYS = {
    "base", "address", "addr", "buffer", "handle", "hkey", "pc", "start_address", "start_addr",
    "ret_val", "return_value", "value", "target", "entry", "image_base", "start", "func", "object",
}


def hx(v: Any) -> Any:
    """Render an int as 0x-hex; leave anything else alone."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, int):
        return hex(v)
    return v


def _pick(d: dict, names: tuple[str, ...]) -> Any:
    for n in names:
        if n in d:
            return d[n]
    return None


def normalize_top(report: dict) -> dict:
    out = {
        "report_version": report.get("report_version"),
        "arch": report.get("arch"),
        "sha256": report.get("sha256"),
        "size": report.get("size"),
        "image_base": hx(report.get("image_base")),
        "emulation_total_runtime": report.get("emulation_total_runtime"),
        "entry_point_count": len(report.get("entry_points") or []),
    }
    for key, names in _TOP_FIELDS.items():
        out[key] = _pick(report, names)
    errs = report.get("errors") or []
    if errs:
        out["session_errors"] = [compact_error(e) for e in errs]
    return out


def normalize_entry(ep: dict) -> dict:
    out = {key: _pick(ep, names) for key, names in _EP_FIELDS.items()}
    out["start_address"] = hx(out["start_address"])
    out["return_value"] = hx(out["return_value"])
    out["args"] = [hx(a) for a in (out["args"] or [])]
    out["pid"] = ep.get("pid")
    out["tid"] = ep.get("tid")
    out["error"] = ep.get("error")
    out["events"] = ep.get("events") or []
    out["dropped_files"] = ep.get("dropped_files") or []
    out["dynamic_code_segments"] = ep.get("dynamic_code_segments") or []
    out["coverage"] = ep.get("coverage")
    out["memory"] = ep.get("memory")
    return out


def compact_error(err: dict | None) -> dict | None:
    """Keep the fields of an error that matter for triage; drop registers and stacks."""
    if not err:
        return None
    keep = (
        "type",
        "message",
        "api_name",
        "last_api",
        "pc",
        "pc_module",
        "pc_offset",
        "instruction",
        "instr",
        "address",
        "access_type",
        "context_summary",
        "count",
        "interrupt_num",
    )
    return {k: hx(err[k]) for k in keep if err.get(k) is not None}


def _event_view(ev: dict, include_pos: bool = False) -> dict:
    out = {}
    for k, v in ev.items():
        if k == "pos" and not include_pos:
            continue
        if k == "args" and isinstance(v, list):
            out[k] = [_arg_view(a) for a in v]
        elif k in _WORD_KEYS:
            out[k] = hx(v)
        else:
            out[k] = v
    if include_pos and isinstance(ev.get("pos"), dict):
        out["pos"] = {k: hx(v) for k, v in ev["pos"].items()}
    return out


def _arg_view(a: Any) -> Any:
    if not isinstance(a, dict):
        return hx(a)
    name = a.get("name")
    disp = a.get("display", hx(a.get("value")))
    return f"{name}={disp}" if name else disp


def _api_line(ev: dict) -> str:
    args = ", ".join(str(_arg_view(a)) for a in ev.get("args") or [])
    ret = ev.get("ret_val", ev.get("return_value"))
    s = f"{ev.get('api_name')}({args})"
    if ret is not None:
        s += f" -> {hx(ret)}"
    pc = (ev.get("pos") or {}).get("pc")
    if pc is not None:
        s = f"[{hx(pc)}] " + s
    return s


def _select_entries(report: dict, entry_index: int | None) -> list[tuple[int, dict]]:
    eps = report.get("entry_points") or []
    if entry_index is None:
        return list(enumerate(eps))
    if not 0 <= entry_index < len(eps):
        raise ValueError(f"entry_index {entry_index} out of range (report has {len(eps)} entry points)")
    return [(entry_index, eps[entry_index])]


def summary(report: dict, top_apis: int = 25) -> dict:
    out = normalize_top(report)
    entries = []
    all_types: Counter[str] = Counter()
    api_counts: Counter[str] = Counter()
    for i, raw in enumerate(report.get("entry_points") or []):
        ep = normalize_entry(raw)
        types = Counter(e.get("event") for e in ep["events"])
        all_types.update(types)
        for e in ep["events"]:
            if e.get("event") == "api":
                api_counts[str(e.get("api_name"))] += 1
        entries.append(
            {
                "index": i,
                "type": ep["type"],
                "name": ep["name"],
                "start_address": ep["start_address"],
                "instruction_count": ep["instruction_count"],
                "return_value": ep["return_value"],
                "event_count": len(ep["events"]),
                "api_call_count": types.get("api", 0),
                "dropped_files": len(ep["dropped_files"]),
                "dynamic_code_segments": len(ep["dynamic_code_segments"]),
                "error": compact_error(ep["error"]),
            }
        )
    out["entry_points"] = entries
    out["event_type_counts"] = dict(all_types.most_common())
    out["top_apis"] = dict(api_counts.most_common(top_apis))
    strings = report.get("strings") or {}
    out["string_counts"] = {
        f"{scope}.{enc}": len((strings.get(scope) or {}).get(enc) or [])
        for scope in ("static", "in_memory")
        for enc in ("ansi", "unicode")
    }
    return out


def api_calls(
    report: dict,
    entry_index: int | None = None,
    name_filter: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> dict:
    pat = name_filter.lower() if name_filter else None
    if pat and not any(c in pat for c in "*?["):
        pat = f"*{pat}*"
    rows = []
    for i, raw in _select_entries(report, entry_index):
        for ev in raw.get("events") or []:
            if ev.get("event") != "api":
                continue
            if pat and not fnmatch.fnmatch(str(ev.get("api_name", "")).lower(), pat):
                continue
            rows.append(f"ep{i} {_api_line(ev)}")
    return {"total": len(rows), "offset": offset, "calls": rows[offset : offset + limit]}


def events(
    report: dict,
    entry_index: int | None = None,
    event_types: list[str] | None = None,
    contains: str | None = None,
    offset: int = 0,
    limit: int = 100,
    include_pos: bool = False,
) -> dict:
    wanted = {t.lower() for t in event_types} if event_types else None
    needle = contains.lower() if contains else None
    rows = []
    for i, raw in _select_entries(report, entry_index):
        for ev in raw.get("events") or []:
            et = ev.get("event")
            if wanted and et not in wanted:
                continue
            view = _event_view(ev, include_pos)
            if needle and needle not in json.dumps(view, default=str).lower():
                continue
            view["entry_index"] = i
            rows.append(view)
    return {"total": len(rows), "offset": offset, "events": rows[offset : offset + limit]}


def iocs(report: dict) -> dict:
    """Group the behaviour that matters for triage into buckets, de-duplicated."""
    buckets: dict[str, list] = {
        "network": [],
        "files": [],
        "registry": [],
        "processes_and_threads": [],
        "modules_loaded": [],
        "exceptions": [],
        "memory_protect": [],
    }
    seen: set[str] = set()
    for i, raw in enumerate(report.get("entry_points") or []):
        for ev in raw.get("events") or []:
            et = ev.get("event", "")
            if et not in IOC_EVENT_TYPES:
                continue
            view = _event_view(ev)
            key = json.dumps(view, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            view["entry_index"] = i
            if et.startswith("net_"):
                buckets["network"].append(view)
            elif et.startswith(("file_", "directory_")):
                buckets["files"].append(view)
            elif et.startswith("reg_"):
                buckets["registry"].append(view)
            elif et in ("process_create", "thread_create", "thread_inject"):
                buckets["processes_and_threads"].append(view)
            elif et == "module_load":
                buckets["modules_loaded"].append(view)
            elif et == "exception":
                buckets["exceptions"].append(view)
            elif et == "mem_protect":
                buckets["memory_protect"].append(view)
        for df in raw.get("dropped_files") or []:
            buckets.setdefault("dropped_files", []).append(
                {"entry_index": i, "path": df.get("path"), "size": df.get("size"), "sha256": df.get("sha256")}
            )
        for seg in raw.get("dynamic_code_segments") or []:
            buckets.setdefault("dynamic_code", []).append(
                {"entry_index": i, "tag": seg.get("tag"), "base": hx(seg.get("base")), "size": seg.get("size")}
            )
    return {k: v for k, v in buckets.items() if v}


def strings(
    report: dict,
    scope: str = "all",
    contains: str | None = None,
    min_length: int = 4,
    offset: int = 0,
    limit: int = 200,
) -> dict:
    data = report.get("strings")
    if not data:
        return {"total": 0, "strings": [], "note": "report has no strings (analysis.strings was off)"}
    scopes = ("static", "in_memory") if scope == "all" else (scope,)
    needle = contains.lower() if contains else None
    rows = []
    for sc in scopes:
        coll = data.get(sc) or {}
        for enc in ("ansi", "unicode"):
            for s in coll.get(enc) or []:
                if len(s) < min_length:
                    continue
                if needle and needle not in s.lower():
                    continue
                rows.append({"scope": sc, "enc": enc, "s": s})
    return {"total": len(rows), "offset": offset, "strings": rows[offset : offset + limit]}


def entry_detail(report: dict, entry_index: int) -> dict:
    [(i, raw)] = _select_entries(report, entry_index)
    ep = normalize_entry(raw)
    mem = ep.pop("memory") or {}
    ep.pop("events")
    cov = ep.pop("coverage")
    ep["coverage_count"] = None if cov is None else len(cov)
    ep["error"] = ep["error"] and {k: hx(v) if not isinstance(v, (dict, list)) else v for k, v in ep["error"].items()}
    ep["dynamic_code_segments"] = [{k: hx(v) for k, v in s.items()} for s in ep["dynamic_code_segments"]]
    ep["modules"] = [
        {"name": m.get("name"), "base": hx(m.get("base")), "size": m.get("size"), "path": m.get("path")}
        for m in (mem.get("modules") or [])
    ]
    ep["memory_region_count"] = len(mem.get("layout") or [])
    return ep


def _decode_artifact(art: dict) -> bytes:
    enc = art.get("encoding", "base64")
    comp = art.get("compression", "none")
    raw = base64.b64decode(art["data"]) if enc == "base64" else art["data"].encode("latin-1")
    if comp == "zlib":
        raw = zlib.decompress(raw)
    elif comp not in ("none", None):
        raise ValueError(f"unknown compression {comp}")
    return raw


def export_data_refs(report: dict, out_dir: str) -> list[dict]:
    """Write every dropped file and dynamic-code snapshot that has a data_ref to out_dir."""
    store = report.get("data") or {}
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for i, raw in enumerate(report.get("entry_points") or []):
        items = [("dropped", d, d.get("path")) for d in raw.get("dropped_files") or []]
        items += [("dyncode", s, f"{s.get('tag')}_{hx(s.get('base'))}") for s in raw.get("dynamic_code_segments") or []]
        for region in (raw.get("memory") or {}).get("layout") or []:
            items.append(("region", region, f"{region.get('tag')}_{hx(region.get('base', region.get('address')))}"))
        for kind, item, label in items:
            ref = item.get("data_ref")
            if not ref or ref not in store:
                continue
            safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in str(label or ref))[-80:]
            dest = os.path.join(out_dir, f"ep{i}_{kind}_{safe}_{ref[:12]}.bin")
            with open(dest, "wb") as f:
                f.write(_decode_artifact(store[ref]))
            written.append({"entry_index": i, "kind": kind, "label": label, "file": dest, "sha256": ref})
    return written
