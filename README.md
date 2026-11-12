# speakeasy-mcp

An MCP server for [Speakeasy](https://github.com/mandiant/speakeasy), Mandiant's Windows malware
emulator. It lets an MCP client (Claude Code, Claude Desktop, etc.) emulate PE files and shellcode,
then query the result without loading a multi-MB JSON report into context.

Speakeasy runs the sample on Unicorn (an emulated CPU) against modelled Windows APIs, file system,
registry and network. Nothing runs natively, and network activity is simulated: a DNS or HTTP event
shows what the sample *tried* to do.

## How Speakeasy was mapped

The input was the `speakeasy-master` source tree (version string `2.0.0b9`). What matters for an
MCP wrapper:

| Finding | Where | Consequence for the server |
|---|---|---|
| The public API is the `speakeasy.Speakeasy` class: `load_module`/`load_shellcode` → `run_module`/`run_shellcode` → `get_json_report`; plus `call`, `mem_read`, `read_mem_string`, `reg_read/write`, `get_mem_maps`, `get_symbols`, `add_api_hook`, `create_file_archive` | `speakeasy/speakeasy.py`, `doc/library.md` | One-shot tools wrap load→run→report. Session tools wrap the rest. |
| One `Speakeasy` object emulates exactly one input; a second load raises `InputError` | `doc/library.md` | One emulator per run or session, each in its own process. |
| The constructor takes `exit_event`, which Speakeasy polls to stop a run cleanly | `Speakeasy.__init__` | The wall-clock timeout sets the event, so a partial report is still written. If the child does not stop, it is killed. |
| The config is a strict pydantic model (`extra="forbid"`) | `speakeasy/config.py` | Overrides are deep-merged into the build's own default config, and validation errors are returned in full. |
| The PyPI wheel 2.0.0b9 writes report **5.0.0** (`ep_type`, `start_addr`, `filetype`, int words). Master writes **6.0.0** (`type`, `start_address`, `file_type`, hex-string words). Config names differ too (`timeout`/`max_api_count` vs `max_run_time`/`max_api_calls`) | `report.py`, `config.py` in both | `reports.py` normalizes both report formats. `worker.py` maps limit names to whichever field the installed build has. |
| Reports hold payloads (dropped files, dynamic-code snapshots, memory snapshots) once, in a top-level `data` store keyed by SHA-256 (zlib + base64) | `doc/reporting.md` | `report_export_artifacts` decodes them to disk. |
| API hooks: `add_api_hook(cb, module, api)` with wildcards. The callback can skip the handler and return its own value | `doc/library.md` | `session_hook_api` forces return values (anti-debug/anti-VM bypass) or records calls. |

## Tools

**One-shot emulation** (each run happens in a fresh `spawn` process and the report is stored under a `run_id`)

- `emulate_pe(path, all_entrypoints, emulate_children, entry_point_rva, argv, volumes, max_run_time, max_api_calls, coverage, memory_tracing, dynamic_code_snapshots, snapshot_memory_regions, config_overrides, timeout_s)`. Drivers get the kernel emulator automatically.
- `emulate_shellcode(path, arch, offset, …)`
- `get_default_config()`, `list_runs()`

**Report queries** (paginated and filterable)

- `report_summary`: input metadata, entry points with errors, event counts, top APIs
- `report_iocs`: network, file, registry, process/thread, module-load, exception, memory-protect, dropped-file and dynamic-code activity, de-duplicated
- `report_api_calls(name_filter="reg*")`: one line per call, `[pc] mod.Api(arg=decoded, …) -> ret`
- `report_events(event_types=[…], contains=…)`
- `report_strings(scope="in_memory")`: strings that appeared in memory but were not in the file
- `report_entry_point`, `report_export_artifacts`, `report_path`

**Interactive sessions** (a persistent emulator in a worker process)

- `session_open` → `session_hook_api` → `session_run` / `session_call("ExportName", [args])`
- `session_read_memory`, `session_read_string`, `session_dump_memory`, `session_write_memory`
- `session_registers`, `session_set_register`, `session_disassemble` (annotates direct and IAT calls), `session_memory_map`, `session_symbols`
- `session_api_hook_hits`, `session_save_report` (makes a `run_id`), `session_close`, `session_list`

## Install and register

```bash
git clone https://github.com/skayyz/speakeasy-mcp && cd speakeasy-mcp
python3 -m venv .venv && .venv/bin/pip install -e .
```

`scripts/run.sh` does that install on first use, then starts the server on stdio. Register it with
Claude Code:

```bash
claude mcp add speakeasy -e SPEAKEASY_MCP_ALLOWED_ROOTS=$HOME/samples -- bash /path/to/speakeasy-mcp/scripts/run.sh
```

or in a project's `.mcp.json`:

```json
"speakeasy": {
  "command": "bash",
  "args": ["/path/to/speakeasy-mcp/scripts/run.sh"],
  "env": { "SPEAKEASY_MCP_ALLOWED_ROOTS": "/path/to/samples" }
}
```

### Claude Code on this repository

Open a Claude Code session (local or cloud) on this repo and the server is already set up:
`.mcp.json` registers `speakeasy` through `scripts/claude-mcp.sh`, and a SessionStart hook in
`.claude/settings.json` installs it into `.venv` before the first call. Inputs and outputs are
confined to `samples/` (gitignored); put samples there.

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `SPEAKEASY_MCP_ALLOWED_ROOTS` | unset (any path) | `:`-separated host dirs that inputs and outputs must sit under |
| `SPEAKEASY_MCP_DATA` | `~/.cache/speakeasy-mcp` | where runs (`runs/<run_id>/report.json`, dropped-file zips) and dumps are stored |
| `SPEAKEASY_MCP_TIMEOUT` | `300` | default wall-clock budget per one-shot job, in seconds |
| `SPEAKEASY_MCP_MAX_SESSIONS` | `4` | concurrent interactive sessions |

`python -m speakeasy_mcp --transport streamable-http --port 8765` serves over HTTP instead of stdio.

To use the newer master branch instead of the PyPI wheel, install it into the venv
(`pip install /path/to/speakeasy-master`). The server handles both report formats.

## Testing

```bash
python -I tests/smoke_test.py <dir with decompressed speakeasy tests/bins programs>
```

The test drives every tool over stdio with a real MCP client. Its inputs are Speakeasy's own
benign test programs: a file-access EXE, a DLL with two exports, a WDM driver, a raw shellcode
blob and an endless API loop that checks the timeout path.

## Limits

- Speakeasy approximates Windows. A sample that needs an unmodelled API stops with an
  `unsupported_api` error. Check `report_summary` → `entry_points[].error`.
- .NET assemblies are not supported (Speakeasy raises `NotSupportedError`).
- Report strings, paths and URLs come from the sample. Treat them as untrusted data.
