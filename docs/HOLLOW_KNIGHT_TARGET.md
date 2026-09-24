# Hollow Knight target inventory

This file records metadata only. Game executables and assets are not part of the
repository. Hashes identify the exact legal, user-supplied Windows build used for
compatibility testing because different releases can expose different APIs.

## Profiled files

| File | Size | SHA-256 |
| --- | ---: | --- |
| `hollow_knight.exe` | 672,256 bytes | `7961bba7243ce322163ad6b0ddfd6ef701413020b92ad0d98502526a396171b0` |
| `UnityPlayer.dll` | 33,736,616 bytes | `8f2d601f8d3c7f4d29d80ba786c0be873102bb7e6041eb03964a90b99724d90b` |

Both are PE32+ x86-64 images. The executable imports only `UnityPlayer.dll` and
`KERNEL32.dll`; its preferred base is `0x140000000` and its entry RVA is
`0x1264`.

`UnityPlayer.dll` has preferred base `0x180000000`, entry RVA `0x199d5ec`, image
size `0x211e000`, eight sections, and both `.pdata` and `.reloc` data. SadLayer's
import inventory currently finds 522 symbols: 484 by name and 38 by ordinal.
The launcher imports `UnityMain2`; SadLayer resolves it to export ordinal 2 at
RVA `0x7da7a0` in this `UnityPlayer.dll`.

With the built-in KERNEL32 bootstrap subset enabled, the current launcher-only
link check against the profiled files resolves 69 symbols and leaves three
unresolved: `FindClose`, `FindFirstFileExW`, and `FindNextFileW`. The check was
rerun against the hashes recorded above after adding `CreateFileW` and
`SetFilePointerEx`; IAT binding remains intentionally skipped until the entire
launcher import set resolves atomically. Disassembly of the two launcher calls
to `CreateFileW` shows the same measured request: `CONOUT$`, generic write
access, read/write sharing, `OPEN_EXISTING`, and zero optional flags. SadLayer
now represents that device with a process-local typed `FILE` token and accepts
it in the console/write/type APIs. General disk paths are deliberately not
claimed by this checkpoint.

The profiled exception directories contain 323 runtime-function entries with
137 distinct unwind records in the launcher and 103,587 entries with 67,501
distinct records in `UnityPlayer.dll`. Each image has four version-2 functions
sharing two version-2 records; measured chain depth reaches one in the launcher
and six in UnityPlayer, with no indirect runtime-function entries. SadLayer now
validates and interprets those static v1/v2 and chained forms. Dynamic function
tables, signal-to-SEH translation, nested/collided and exit unwinds, and special
long-jump/consolidation restores remain unsupported.

The launcher's CRT path reads `GS:[0x30]` and `GS:[0x60]` before reaching
`UnityMain2`, then consumes TEB stack bounds and PEB process parameters. A
GS-backed synthetic TEB/PEB is therefore a measured entry-point requirement,
not merely a later compatibility enhancement.

The isolated synthetic worker now exercises those exact GS offsets from PE
code, validates the PEB image base and stack bounds, calls KERNEL32 through its
bound IAT, and returns while preserving the parent GS state. Crash fixtures hit
the lower stack guard page and emit signal/code, fault address, RIP, and RSP
from a guarded alternate signal stack. One deliberately sets RSP to zero first,
proving that the report survives destruction of the guest stack and that the
parent remains usable.

The synthetic process path can now adopt one completely bound and finalized
module space, keep the exact main PE plus a private UTF-16 image-path copy, and
derive `PEB.ImageBaseAddress` and worker execution from that same identity.
Read-only getters expose those values without reopening loader mutation after
publication. The module-query cluster now operates through that active process
context: `GetModuleHandleW` and `GetModuleHandleExW` expose PE mapping bases by
basename or mapped address, `GetProcAddress` resolves named and ordinal exports
plus forwarders, and `RtlPcToFileHeader` identifies the PE range containing a
program counter. Module pin/reference-count flags do not change lifetime yet
because every adopted module remains resident. `LoadLibraryExW` now reacquires
those existing PE mappings by basename for the default and measured
System32-search requests; `FreeLibrary` validates their handles but deliberately
does not unload them. `GetModuleFileNameW` returns the real copied main-image
path and follows modern null-terminated truncation behavior. Path-bearing
lookups remain rejected until the loader owns canonical paths for every DLL,
and native built-ins still have no `HMODULE`. This closes an ownership and
image-substitution gap, but it does not make the profiled game graph runnable.

The execution mapper now reserves this launcher at `0x140000000` on the profiled
host, applies its final page protections, and identifies the entry address as
`0x140001264`. SadLayer still does not transfer control to it: the remaining
launcher imports, recursive UnityPlayer dependency binding, initialization
order, API Set routing, and PE TLS are explicit gates. The next
launcher-specific work is the three directory-search imports followed by
recursive module discovery/loading.

## Direct UnityPlayer modules

- Process/runtime: `KERNEL32`, `ADVAPI32`, `VERSION`, `SHLWAPI`, `SETUPAPI`.
- Window and input: `USER32`, `GDI32`, `IMM32`, `HID`, `dwmapi`.
- Graphics: `OPENGL32`, `d3d11`, `dxgi`.
- Audio: `WINMM`.
- COM/WinRT: `ole32`, `OLEAUT32`, and two WinRT API Set contracts.
- Network/security: `WS2_32`, `WINHTTP`, `IPHLPAPI`, `bcrypt`, `CRYPT32`.
- Synchronization: `api-ms-win-core-synch-l1-2-0`.
- Shell: `SHELL32`.

API Set names are contracts, not separate platform backends. The module registry
now has an explicit one-hop alias primitive that routes imports and forwarders to
an already registered host module. Populating the real contract mappings and
integrating Windows API Set schema/policy remain loader gates.

## Loader implications

The first loader path must support x86-64 base relocations, named and ordinal
imports, API Set aliases, DLL export lookup, IAT patching, TLS inspection, and
x64 unwind metadata. Generic alias-aware import/IAT/forwarder plumbing now
exists, and explicitly supplied PE files can now share an owning module space;
PE-only handle/address lookup and the process-local module-query cluster are
also in place. Recursive discovery and authoritative mappings for the target
contracts are still required.
The inventory does not prove which graphics path is chosen at runtime, so both
imported graphics families remain candidates until tracing captures the actual
initialization path.

Reproduce the symbol count with:

```sh
./build/sadlayer imports "/path/to/UnityPlayer.dll"
```
