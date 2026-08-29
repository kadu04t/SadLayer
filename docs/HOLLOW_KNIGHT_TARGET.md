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
link check resolves 53 symbols and leaves 19 unresolved. The unresolved set is
concentrated in x64 exception/unwind, dynamic module management, filesystem
search/file positioning, and file creation. IAT binding remains intentionally
skipped until the entire launcher import set resolves atomically.

The launcher's CRT path reads `GS:[0x30]` and `GS:[0x60]` before reaching
`UnityMain2`, then consumes TEB stack bounds and PEB process parameters. A
GS-backed synthetic TEB/PEB is therefore a measured entry-point requirement,
not merely a later compatibility enhancement.

## Direct UnityPlayer modules

- Process/runtime: `KERNEL32`, `ADVAPI32`, `VERSION`, `SHLWAPI`, `SETUPAPI`.
- Window and input: `USER32`, `GDI32`, `IMM32`, `HID`, `dwmapi`.
- Graphics: `OPENGL32`, `d3d11`, `dxgi`.
- Audio: `WINMM`.
- COM/WinRT: `ole32`, `OLEAUT32`, and two WinRT API Set contracts.
- Network/security: `WS2_32`, `WINHTTP`, `IPHLPAPI`, `bcrypt`, `CRYPT32`.
- Synchronization: `api-ms-win-core-synch-l1-2-0`.
- Shell: `SHELL32`.

API Set names are contracts that the future module resolver must redirect to
SadLayer implementations; they are not separate platform backends.

## Loader implications

The first loader path must support x86-64 base relocations, named and ordinal
imports, API Set aliases, DLL export lookup, IAT patching, TLS inspection, and
x64 unwind metadata. The inventory does not prove which graphics path is chosen
at runtime, so both imported graphics families remain candidates until tracing
captures the actual initialization path.

Reproduce the symbol count with:

```sh
./build/sadlayer imports "/path/to/UnityPlayer.dll"
```
