"""Runtime fixes for Speakeasy's memory-protection API handlers.

Speakeasy 2.0.0b9 (and master at the time of writing) models VirtualProtect & co. loosely enough
that common unpacker stubs crash or misbehave. ``apply()`` replaces the affected handlers on the
handler classes, so it must run before a ``Speakeasy`` object is created (handlers are collected
per instance from their ``__apihook__`` attribute in ``ApiHandler.__init__``).

Fixed:

1. VirtualProtect sized the range from ``dwSize`` alone, ignoring ``lpAddress``'s offset in its
   page: a 4-byte protect at 0x...ffd changed one page, not two, so the write faulted.
2. VirtualProtect stored the new protection on the whole MemMap (``mm.prot = new``) even when only
   part of it changed, so VirtualQuery and the next "old protection" were wrong for other pages.
3. The old protection came from ``mm.flags`` (the VirtualAlloc protection) whenever set, so it was
   stale after the first change: alloc RW, protect RX, protect RW -> reported old = RW.
4. A range running past the mapped memory raised ``UcError`` out of the handler, ending the run.
5. PAGE_WRITECOPY / PAGE_EXECUTE_WRITECOPY mapped to no access at all.
6. Failures did not set the last error; a NULL ``lpflOldProtect``, an invalid protection value or
   released memory were not rejected the way Windows rejects them.
7. VirtualQuery reported the whole MemMap as one region with its base and the map-level
   protection, ignoring per-page protections, and always returned ``Type = 0``. A loaded image
   is one MemMap whose ``prot`` is RWX while the engine holds the real per-section protections,
   so every image page (``.text`` included) was reported as PAGE_EXECUTE_READWRITE, by both
   VirtualQuery and VirtualProtect's old protection.
8. Kernel-mode ZwProtectVirtualMemory was a no-op that left ``*OldAccessProtection`` unwritten.
9. User-mode ntdll had no NtProtectVirtualMemory / ZwProtectVirtualMemory handler at all.
"""

from __future__ import annotations

import bisect
from typing import Any

PAGE = 0x1000
PAGE_MASK = ~(PAGE - 1)

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_MODIFIERS = 0x100 | 0x200 | 0x400  # GUARD, NOCACHE, WRITECOMBINE

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

ERROR_INVALID_PARAMETER = 87
ERROR_INVALID_ADDRESS = 487
ERROR_NOACCESS = 998

STATUS_SUCCESS = 0
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_CONFLICTING_ADDRESSES = 0xC0000018
STATUS_NOT_COMMITTED = 0xC000002D
STATUS_INVALID_PAGE_PROTECTION = 0xC0000045

_applied = False


# --------------------------------------------------------------------------- protection helpers


def _emu_perms(win_prot: int) -> int | None:
    """Windows PAGE_* value -> speakeasy PERM_MEM_* value, or None if it is not a valid value."""
    import speakeasy.common as c

    table = {
        PAGE_NOACCESS: c.PERM_MEM_NONE,
        PAGE_READONLY: c.PERM_MEM_READ,
        PAGE_READWRITE: c.PERM_MEM_RW,
        PAGE_WRITECOPY: c.PERM_MEM_RW,  # copy-on-write: the emulated process owns its pages
        PAGE_EXECUTE: c.PERM_MEM_EXEC,
        PAGE_EXECUTE_READ: c.PERM_MEM_RX,
        PAGE_EXECUTE_READWRITE: c.PERM_MEM_RWX,
        PAGE_EXECUTE_WRITECOPY: c.PERM_MEM_RWX,
    }
    if win_prot & ~(0xFF | PAGE_MODIFIERS):
        return None
    return table.get(win_prot & 0xFF)  # exactly one base protection bit, or invalid


def _win_prot(emu_perms: int) -> int:
    import speakeasy.common as c

    w, x, r = emu_perms & c.PERM_MEM_WRITE, emu_perms & c.PERM_MEM_EXEC, emu_perms & c.PERM_MEM_READ
    if w:
        return PAGE_EXECUTE_READWRITE if x else PAGE_READWRITE
    if x:
        return PAGE_EXECUTE_READ if r else PAGE_EXECUTE
    return PAGE_READONLY if r else PAGE_NOACCESS


def _fixed_win_perms_to_emu_perms(self, win_perms):
    """Replacement for the handlers' converter: same results, except WRITECOPY variants."""
    perms = _emu_perms(win_perms)
    if perms is not None:
        return perms
    return _orig_converter(self, win_perms)  # invalid value: keep Speakeasy's old answer


_orig_converter: Any = None


class _PageState:
    """Current per-page protection, read from the CPU engine (the source of truth for access
    checks) plus the exact PAGE_* value last set, which the engine cannot represent (WRITECOPY,
    GUARD, ...). A stored value is only trusted while it still agrees with the engine."""

    def __init__(self, emu: Any):
        self.emu = emu
        eng = emu.emu_eng
        self._uc_to_perm = {v: k for k, v in eng.perms.items()}
        regions = sorted(eng.emu.mem_regions())  # (begin, end_inclusive, uc_perms)
        self._starts = [r[0] for r in regions]
        self._regions = regions
        table = getattr(emu, "_speakeasy_mcp_page_prot", None)
        if table is None:
            table = {}
            emu._speakeasy_mcp_page_prot = table
        self.table: dict[int, int] = table
        self._last_mm: Any = None

    def map_for(self, addr: int) -> Any:
        mm = self._last_mm
        if mm is None or not (mm.base <= addr < mm.base + mm.size):
            mm = self.emu.get_address_map(addr)
            self._last_mm = mm
        return mm

    def engine_perms(self, addr: int) -> int | None:
        i = bisect.bisect_right(self._starts, addr) - 1
        if i < 0:
            return None
        begin, end, uc_perms = self._regions[i]
        if addr > end:
            return None
        return self._uc_to_perm.get(uc_perms, uc_perms)

    def mapped(self, start: int, end: int) -> bool:
        a = start
        while a < end:
            i = bisect.bisect_right(self._starts, a) - 1
            if i < 0 or a > self._regions[i][1]:
                return False
            a = self._regions[i][1] + 1
        return True

    def protection(self, page: int) -> int:
        perms = self.engine_perms(page)
        if perms is None:
            return PAGE_NOACCESS
        stored = self.table.get(page)
        if stored is not None and _emu_perms(stored) == perms:
            return stored
        mm = self.map_for(page)
        if mm is not None and mm.flags and _emu_perms(mm.flags) == perms:
            return mm.flags
        return _win_prot(perms)


def _protect(emu: Any, address: int, size: int, new_prot: int):
    """Shared core. Returns (ok, old_prot, base, region_size, win32_error, ntstatus)."""
    perms = _emu_perms(new_prot)
    if perms is None:
        return False, 0, 0, 0, ERROR_INVALID_PARAMETER, STATUS_INVALID_PAGE_PROTECTION

    start = address & PAGE_MASK
    end = (address + max(size, 1) + PAGE - 1) & PAGE_MASK

    mm = emu.get_address_map(address)
    if mm is None or getattr(mm, "free", False):
        return False, 0, 0, 0, ERROR_INVALID_ADDRESS, STATUS_NOT_COMMITTED

    # Windows rejects a range that leaves the allocation (an image counts as one allocation even
    # though Speakeasy maps each section separately) or that hits unmapped pages.
    alloc_base, alloc_end, _ = _allocation(emu, mm)
    state = _PageState(emu)
    if start < (alloc_base & PAGE_MASK) or end > alloc_end or not state.mapped(start, end):
        return False, 0, 0, 0, ERROR_INVALID_ADDRESS, STATUS_CONFLICTING_ADDRESSES

    old = state.protection(start)  # Windows reports the first page's protection
    emu.mem_protect(start, end - start, perms)
    for page in range(start, end, PAGE):
        state.table[page] = new_prot
    if start <= mm.base and mm.base + mm.size <= end:
        mm.prot = perms  # only when the whole map changed
    return True, old, start, end - start, 0, STATUS_SUCCESS


def _write_u32(handler: Any, addr: int, value: int) -> bool:
    try:
        handler.mem_write(addr, (value & 0xFFFFFFFF).to_bytes(4, "little"))
        return True
    except Exception:
        return False


def _read_ptr(handler: Any, emu: Any, addr: int) -> int | None:
    try:
        return int.from_bytes(handler.mem_read(addr, emu.get_ptr_size()), "little")
    except Exception:
        return None


def _set_display(ctx: Any, name: str, text: str) -> None:
    try:
        ctx.args[name].display = text
    except Exception:
        pass


# --------------------------------------------------------------------------- handlers


def _virtual_protect(self, emu, argv, ctx=None):
    """BOOL WINAPI VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect,
    PDWORD lpflOldProtect);"""
    lpAddress, dwSize, flNewProtect, lpflOldProtect = argv
    if not lpflOldProtect:
        emu.set_last_error(ERROR_NOACCESS)
        return 0
    ok, old, _, _, err, _ = _protect(emu, lpAddress, dwSize, flNewProtect)
    if not ok:
        emu.set_last_error(err)
        return 0
    if not _write_u32(self, lpflOldProtect, old):
        emu.set_last_error(ERROR_NOACCESS)
        return 0
    return 1


def _virtual_query(self, emu, argv, ctx=None):
    """SIZE_T VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength);"""
    lpAddress, lpBuffer, dwLength = argv
    mbi = self.k32types.MEMORY_BASIC_INFORMATION(emu.get_ptr_size())
    if mbi.sizeof() > dwLength or not lpBuffer:
        emu.set_last_error(ERROR_INVALID_PARAMETER)
        return 0
    mm = emu.get_address_map(lpAddress)
    if not mm:
        emu.set_last_error(ERROR_INVALID_PARAMETER)
        return 0

    state = _PageState(emu)
    page = lpAddress & PAGE_MASK
    prot = state.protection(page)
    # Windows reports the run of pages, within the same allocation, with identical attributes.
    alloc_base, alloc_end, mem_type = _allocation(emu, mm)
    end = page + PAGE
    while end < alloc_end and state.engine_perms(end) is not None and state.protection(end) == prot:
        end += PAGE

    if mem_type == MEM_IMAGE:
        alloc_prot = PAGE_EXECUTE_WRITECOPY  # what Windows reports for every image allocation
    else:
        alloc_prot = mm.flags if mm.flags else _win_prot(mm.prot if mm.prot is not None else 0)
    mbi.BaseAddress = page
    mbi.AllocationBase = alloc_base
    mbi.AllocationProtect = alloc_prot
    mbi.RegionSize = end - page
    mbi.State = MEM_COMMIT
    mbi.Protect = prot
    mbi.Type = mem_type
    self.mem_write(lpBuffer, mbi.get_bytes())
    return mbi.sizeof()


def _allocation(emu: Any, mm: Any) -> tuple[int, int, int]:
    """(AllocationBase, end of allocation, Type) for a MemMap. Image sections are separate maps in
    Speakeasy but one allocation on Windows."""
    tag = mm.tag or ""
    if tag.startswith("emu.module."):
        mod = None
        try:
            mod = emu.get_mod_from_addr(mm.base)
        except Exception:
            pass
        if mod is not None and getattr(mod, "image_size", None):
            return mod.base, mod.base + mod.image_size, MEM_IMAGE
        return mm.base, mm.base + mm.size, MEM_IMAGE
    mem_type = MEM_MAPPED if "MapViewOf" in tag else MEM_PRIVATE
    return mm.base, mm.base + mm.size, mem_type


def _nt_protect(self, emu, argv, ctx=None):
    """NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);"""
    hnd, pbase, psize, new_prot, pold = argv
    if not pbase or not psize or not pold:
        return STATUS_ACCESS_VIOLATION
    addr = _read_ptr(self, emu, pbase)
    size = _read_ptr(self, emu, psize)
    if addr is None or size is None:
        return STATUS_ACCESS_VIOLATION
    _set_display(ctx, "BaseAddress", hex(addr))
    _set_display(ctx, "RegionSize", hex(size))
    _set_display(ctx, "NumberOfBytesToProtect", hex(size))

    mask = (1 << (8 * emu.get_ptr_size())) - 1
    if (hnd & mask) != mask:  # only NtCurrentProcess() is modelled
        if not self.get_object_from_handle(hnd):
            return STATUS_INVALID_HANDLE

    ok, old, base, region, _, status = _protect(emu, addr, size, new_prot)
    if not ok:
        return status
    ptr = emu.get_ptr_size()
    try:
        self.mem_write(pbase, base.to_bytes(ptr, "little"))
        self.mem_write(psize, region.to_bytes(ptr, "little"))
    except Exception:
        return STATUS_ACCESS_VIOLATION
    if not _write_u32(self, pold, old):
        return STATUS_ACCESS_VIOLATION
    return STATUS_SUCCESS


# --------------------------------------------------------------------------- install


def _hook(cls: type, attr: str, impl: Any, impname: str, argc: int, conv: Any = None) -> None:
    from speakeasy.winenv import arch

    def handler(self, emu, argv, ctx=None):
        return impl(self, emu, argv, ctx)

    handler.__name__ = attr
    handler.__doc__ = impl.__doc__
    handler.__apihook__ = (impname, handler, argc, conv or arch.CALL_CONV_STDCALL, None)
    setattr(cls, attr, handler)


def apply() -> None:
    """Install the fixes. Idempotent; call before constructing ``speakeasy.Speakeasy``."""
    global _applied, _orig_converter
    if _applied:
        return
    from speakeasy.winenv.api.kernelmode.ntoskrnl import Ntoskrnl
    from speakeasy.winenv.api.usermode.kernel32 import Kernel32
    from speakeasy.winenv.api.usermode.ntdll import Ntdll

    _orig_converter = Kernel32.win_perms_to_emu_perms
    for cls in (Kernel32, Ntoskrnl):
        cls.win_perms_to_emu_perms = _fixed_win_perms_to_emu_perms

    _hook(Kernel32, "VirtualProtect", _virtual_protect, "VirtualProtect", 4)
    _hook(Kernel32, "VirtualQuery", _virtual_query, "VirtualQuery", 3)
    # VirtualProtectEx calls self.VirtualProtect, so it picks up the fix as is.
    _hook(Ntoskrnl, "ZwProtectVirtualMemory", _nt_protect, "ZwProtectVirtualMemory", 5)
    _hook(Ntdll, "NtProtectVirtualMemory", _nt_protect, "NtProtectVirtualMemory", 5)
    _hook(Ntdll, "ZwProtectVirtualMemory", _nt_protect, "ZwProtectVirtualMemory", 5)
    _applied = True
