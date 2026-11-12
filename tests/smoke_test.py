"""End-to-end test: start the server over stdio and drive it with an MCP client.

Usage: python -I tests/smoke_test.py <dir with speakeasy test binaries>
Expects file_access_test_x86.exe, dll_test_x86.dll, wdm_test_x86.sys and sc2.bin from
speakeasy's tests/bins (decompress the .xz files first).
"""

import asyncio
import json
import os
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BINS = sys.argv[1]
FAILS = []


def show(title, res):
    if res.is_error:
        FAILS.append(title)
    if len(res.content) > 1:
        FAILS.append(f"{title}: {len(res.content)} content blocks")
    text = res.content[0].text if res.content else ""
    try:
        text = json.dumps(json.loads(text), indent=1)
    except Exception:
        pass
    print(f"\n=== {title} {'(ERROR)' if res.is_error else ''}\n{text[:1800]}")
    try:
        return json.loads(res.content[0].text)
    except Exception:
        return res.content[0].text if res.content else None


async def main():
    env = dict(os.environ, SPEAKEASY_MCP_DATA=tempfile.mkdtemp(prefix="smcp-"))
    params = StdioServerParameters(command=sys.executable, args=["-I", "-m", "speakeasy_mcp"], env=env)
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        tools = await s.list_tools()
        print("tools:", len(tools.tools))

        exe = show("emulate_pe exe", await s.call_tool("emulate_pe", {"path": f"{BINS}/file_access_test_x86.exe"}))
        rid = exe["run_id"]
        show("report_iocs", await s.call_tool("report_iocs", {"run_id": rid}))
        show("report_api_calls *File*", await s.call_tool("report_api_calls", {"run_id": rid, "name_filter": "file", "limit": 8}))
        show("report_events file_*", await s.call_tool("report_events", {"run_id": rid, "event_types": ["file_open", "file_read"], "limit": 3}))
        show("report_strings", await s.call_tool("report_strings", {"run_id": rid, "contains": "txt", "limit": 5}))
        show("report_entry_point", await s.call_tool("report_entry_point", {"run_id": rid, "entry_index": 0}))

        dll = show("emulate_pe dll all_entrypoints", await s.call_tool(
            "emulate_pe", {"path": f"{BINS}/dll_test_x86.dll", "all_entrypoints": True, "dynamic_code_snapshots": True}))
        show("report_export_artifacts", await s.call_tool("report_export_artifacts", {"run_id": dll["run_id"]}))

        show("emulate_pe driver", await s.call_tool("emulate_pe", {"path": f"{BINS}/wdm_test_x86.sys", "all_entrypoints": True}))
        show("emulate_shellcode", await s.call_tool(
            "emulate_shellcode", {"path": f"{BINS}/sc2.bin", "arch": "x86", "max_run_time": 20}))
        show("bad config override", await s.call_tool(
            "emulate_pe", {"path": f"{BINS}/file_access_test_x86.exe", "config_overrides": {"no_such_field": 1}}))

        to = show("timeout path", await s.call_tool("emulate_pe", {
            "path": f"{BINS}/api_loop_x86.exe", "max_run_time": 0, "max_api_calls": 100000000,
            "timeout_s": 5, "strings": False}))
        if not (to.get("status") == "stopped_at_timeout" and "summary" in to):
            FAILS.append("timeout path did not stop cleanly with a report")

        # Interactive session on the DLL
        so = show("session_open dll", await s.call_tool("session_open", {"path": f"{BINS}/dll_test_x86.dll"}))
        sid = so["session_id"]
        show("session_hook_api", await s.call_tool("session_hook_api", {"session_id": sid, "module": "kernel32", "api": "*"}))
        show("session_run", await s.call_tool("session_run", {"session_id": sid}))
        exports = [e["name"] for e in so["exports"] if e["name"]]
        if exports:
            show(f"session_call {exports[0]}", await s.call_tool("session_call", {"session_id": sid, "target": exports[0], "args": [1, 2]}))
            show("session_disassemble", await s.call_tool("session_disassemble", {"session_id": sid, "address": exports[0], "count": 8}))
        show("session_read_memory", await s.call_tool("session_read_memory", {"session_id": sid, "address": so["base"], "size": 64}))
        show("session_read_string", await s.call_tool("session_read_string", {"session_id": sid, "address": so["base"]}))
        show("session_registers", await s.call_tool("session_registers", {"session_id": sid}))
        show("session_memory_map", await s.call_tool("session_memory_map", {"session_id": sid, "tag_filter": "module", "limit": 5}))
        show("session_symbols", await s.call_tool("session_symbols", {"session_id": sid, "contains": "GetProcAddress", "limit": 3}))
        show("session_api_hook_hits", await s.call_tool("session_api_hook_hits", {"session_id": sid, "limit": 5}))
        sr = show("session_save_report", await s.call_tool("session_save_report", {"session_id": sid}))
        show("report_summary of session", await s.call_tool("report_summary", {"run_id": sr["run_id"]}))
        show("session_close", await s.call_tool("session_close", {"session_id": sid}))
        show("list_runs", await s.call_tool("list_runs", {}))

    expected_errors = {"bad config override"}
    unexpected = [f for f in FAILS if f not in expected_errors]
    print("\nUNEXPECTED FAILURES:", unexpected or "none")
    sys.exit(1 if unexpected else 0)


asyncio.run(main())
