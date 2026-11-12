"""Checks for speakeasy_mcp.emu_fixes. Needs no sample binaries.

    python -I tests/test_emu_fixes.py          # expects every check to pass with the fixes
"""

from __future__ import annotations

import logging
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)

import speakeasy  # noqa: E402
import speakeasy.common as common  # noqa: E402
import unicorn as uc  # noqa: E402
from speakeasy.winenv.api import api  # noqa: E402

from speakeasy_mcp import emu_fixes  # noqa: E402

PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY = 0x02, 0x04, 0x08
PAGE_EXECUTE_READ, PAGE_EXECUTE_WRITECOPY = 0x20, 0x80
C = api.NO_CONTEXT
I32 = lambda v: struct.pack("<I", v & 0xFFFFFFFF)  # noqa: E731
FAILS: list[str] = []


def check(name: str, cond: bool, detail: object = "") -> None:
    print(f"{'ok  ' if cond else 'FAIL'} {name} {detail}")
    if not cond:
        FAILS.append(name)


def new_emu(tmp: str, code_size: int = 1):
    path = os.path.join(tmp, "sc.bin")
    with open(path, "wb") as f:
        f.write(b"\x90" * code_size)
    se = speakeasy.Speakeasy()
    base = se.load_shellcode(path, "x86")
    return se, base


def unit_checks(tmp: str) -> None:
    se, _ = new_emu(tmp)
    emu = se.emu
    k32 = emu.api.load_api_handler("kernel32")
    out = emu.mem_map(0x1000, tag="out")

    def alloc(n, prot):
        return k32.VirtualAlloc(emu, [0, n, 0x3000, prot], C)

    def uc_prot(a):
        for b, e, p in emu.emu_eng.emu.mem_regions():
            if b <= a <= e:
                return p

    def vp(a, n, prot):
        r = k32.VirtualProtect(emu, [a, n, prot, out], C)
        return r, struct.unpack("<I", emu.mem_read(out, 4))[0]

    def vq(a):
        buf = emu.mem_map(0x1000, tag="mbi")
        k32.VirtualQuery(emu, [a, buf, 28], C)
        keys = ("Base", "AllocBase", "AllocProt", "Size", "State", "Protect", "Type")
        return dict(zip(keys, struct.unpack("<7I", emu.mem_read(buf, 28))))

    b = alloc(0x2000, PAGE_EXECUTE_READ)
    vp(b + 0xFFD, 4, PAGE_READWRITE)
    check("cross-page protect changes both pages", bool(uc_prot(b + 0x1000) & uc.UC_PROT_WRITE))

    b = alloc(0x3000, PAGE_READWRITE)
    vp(b + 0x1000, 0x1000, PAGE_EXECUTE_READ)
    q = vq(b + 0x2000)
    check("partial protect leaves other pages", q["Protect"] == PAGE_READWRITE, hex(q["Protect"]))
    check("VirtualQuery region is per page run", (q["Base"], q["Size"]) == (b + 0x2000, 0x1000))
    check("VirtualQuery Type/AllocationProtect", (q["Type"], q["AllocProt"]) == (0x20000, PAGE_READWRITE))

    b = alloc(0x1000, PAGE_READWRITE)
    vp(b, 0x1000, PAGE_EXECUTE_READ)
    check("old protection is current, not VirtualAlloc's", vp(b, 0x1000, PAGE_READWRITE)[1] == PAGE_EXECUTE_READ)

    b = alloc(0x1000, PAGE_READONLY)
    vp(b, 0x1000, PAGE_WRITECOPY)
    check("PAGE_WRITECOPY is readable", bool(uc_prot(b) & uc.UC_PROT_READ))
    vp(b, 0x1000, PAGE_EXECUTE_WRITECOPY)
    check("PAGE_EXECUTE_WRITECOPY is executable", bool(uc_prot(b) & uc.UC_PROT_EXEC))
    check("WRITECOPY reported back exactly", vp(b, 0x1000, PAGE_READONLY)[1] == PAGE_EXECUTE_WRITECOPY)

    b = alloc(0x1000, PAGE_READWRITE)
    try:
        r = vp(b, 0x2000, PAGE_READONLY)[0]
    except Exception as e:  # unpatched: UcError escapes the handler
        r = f"{type(e).__name__}"
    check("range past allocation fails cleanly", r == 0, r)
    check("unmapped address fails", vp(0x10, 4, PAGE_READWRITE)[0] == 0)
    check("NULL lpflOldProtect fails", k32.VirtualProtect(emu, [b, 4, PAGE_READWRITE, 0], C) == 0)
    check("invalid protection fails", vp(b, 4, 0)[0] == 0)
    k32.VirtualFree(emu, [b, 0, 0x8000], C)
    check("released memory fails", vp(b, 4, PAGE_READONLY)[0] == 0)
    check("ntdll NtProtectVirtualMemory hooked", "NtProtectVirtualMemory" in emu.api.load_api_handler("ntdll").funcs)


def emulated_checks(tmp: str) -> None:
    """x86 code doing what an unpacker stub does, run by the emulator itself."""
    se, base = new_emu(tmp, 0x400)
    emu = se.emu
    t = emu.mem_map(0x2000, perms=common.PERM_MEM_RX, tag="test.rx")
    d = emu.mem_map(0x1000, perms=common.PERM_MEM_RW, tag="test.data")
    emu.mem_write(d + 0x10, I32(emu.get_proc("kernel32", "VirtualProtect")))
    emu.mem_write(d + 0x14, I32(emu.get_proc("ntdll", "NtProtectVirtualMemory")))
    emu.mem_write(d + 0x18, I32(emu.get_proc("kernel32", "GetLastError")))
    emu.mem_write(d + 0x24, I32(4))
    emu.mem_write(d + 0x28, I32(t + 0x1FF0))

    def call(slot):
        return b"\xff\x15" + I32(d + slot)

    code = b"".join([
        # VirtualProtect(t+0xffd, 4, RW, d); *(t+0xffd) = 0x41414141
        b"\x68" + I32(d), b"\x6a\x04", b"\x6a\x04", b"\x68" + I32(t + 0xFFD), call(0x10),
        b"\xa3" + I32(d + 4), b"\xc7\x05" + I32(t + 0xFFD) + I32(0x41414141),
        # VirtualProtect(t+0x1000, 0x2000, RW, d) runs into the next allocation
        b"\x68" + I32(d), b"\x6a\x04", b"\x68" + I32(0x2000), b"\x68" + I32(t + 0x1000), call(0x10),
        b"\xa3" + I32(d + 0xC), call(0x18), b"\xa3" + I32(d + 0x30),
        # NtProtectVirtualMemory(-1, &base, &size, PAGE_READONLY, d+0x20)
        b"\x68" + I32(d + 0x20), b"\x6a\x02", b"\x68" + I32(d + 0x24), b"\x68" + I32(d + 0x28),
        b"\x6a\xff", call(0x14), b"\xa3" + I32(d + 8),
        b"\xc3",
    ])
    emu.mem_write(base, code)
    se.run_shellcode(base)

    def rd(o):
        return struct.unpack("<I", bytes(emu.mem_read(d + o, 4)))[0]

    written = struct.unpack("<I", bytes(emu.mem_read(t + 0xFFD, 4)))[0]
    check("emulated: page-straddling write succeeds", written == 0x41414141, hex(written))
    check("emulated: old protection PAGE_EXECUTE_READ", rd(0) == PAGE_EXECUTE_READ, hex(rd(0)))
    check("emulated: cross-allocation protect -> ERROR_INVALID_ADDRESS", (rd(0xC), rd(0x30)) == (0, 487))
    check("emulated: NtProtectVirtualMemory", (rd(8), rd(0x28), rd(0x24), rd(0x20)) == (0, t + 0x1000, 0x1000, PAGE_READWRITE),
          [hex(rd(o)) for o in (8, 0x28, 0x24, 0x20)])


if __name__ == "__main__":
    emu_fixes.apply()
    with tempfile.TemporaryDirectory() as tmp:
        unit_checks(tmp)
        emulated_checks(tmp)
    print(f"\n{len(FAILS)} failed" if FAILS else "\nall passed")
    sys.exit(1 if FAILS else 0)
