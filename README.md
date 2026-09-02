# SadLayer

SadLayer is an experimental, clean-room Windows compatibility layer for Linux.
Its first concrete target is reaching the title screen of the Windows build of
Hollow Knight. It is **not usable for running games yet**.

The project starts from the executable boundary: understand and map PE images,
provide a Win32 ABI, connect graphics/audio/input to native Linux backends, and
then execute Windows x86-64 code directly on an x86-64 Linux host. It does not
reuse Wine or Proton source code.

## Current state

The bootstrap can already:

- validate PE32 and PE32+ headers with bounds checks;
- describe architecture, subsystem, entry point, sections, and imported DLLs;
- enumerate imported symbols by name or ordinal and report their IAT RVAs;
- resolve DLL exports by name or ordinal, including forwarded exports;
- translate RVAs to file offsets;
- map headers and sections into an in-memory image;
- apply PE32 `HIGHLOW` and PE32+ `DIR64` base relocations atomically;
- reserve address-stable PE32+ images with non-destructive Linux `mmap`, fall
  back through relocation when the preferred base is occupied, and apply final
  per-page PE protections with a strict W^X check;
- register mapped PE and native modules, copy explicit module aliases, and
  resolve imports and mixed forwarder chains through the aliased host module;
- bind PE32/PE32+ import address tables without partial writes;
- expose an initial 54-export `KERNEL32.dll` subset through x86-64 `ms_abi`
  thunks for last-error state, time/identity, heap, TLS, no-fiber FLS, critical
  sections, text conversion, process strings, locale basics, standard streams,
  pointer encoding, and process termination;
- create explicit guest process objects with an OS-random pointer cookie used by
  the reversible `EncodePointer`/`DecodePointer` pair;
- convert explicit-length UTF-8/UTF-16 strictly or with replacement, without
  exposing Linux `wchar_t` at the Windows boundary;
- install nestable per-thread runtime contexts and route last-error, thread
  identity, TLS, and no-fiber FLS state through them;
- construct the measured PEB/process-parameters and guarded TEB memory layouts,
  sharing `TEB+0x68` with the KERNEL32 last-error thunk;
- execute a trusted synthetic PE32+ entry point that calls native KERNEL32
  functions through its bound IAT and returns normally to Linux;
- run the GS-aware synthetic entry point in an isolated copy-on-write process
  on a 1 MiB stack between guard pages, install and restore the TEB through GS,
  normalize inherited signal state, observe `ExitProcess`/`TerminateProcess`,
  and contain fatal guest signals without losing the parent;
- report handled crashes from a guarded 128 KiB alternate signal stack through
  a fixed-width record containing signal/code, fault address, RIP, and RSP;
  the report still arrives when a fixture destroys its guest RSP before hitting
  the lower stack guard page;
- classify the first Win32 DLL targets needed by the runtime;
- reject malformed and unsupported images with explicit errors.

Module aliases are explicit, bounded, case-insensitive, and one-hop: each alias
must target an already registered module. This is shared plumbing for imports,
IAT binding, and forwarders, not complete API Set support. SadLayer does not yet
read an API Set schema or populate the target build's contract-to-host mappings.

The native KERNEL32 surface is a host-backed bootstrap subset, not a complete
Windows process environment. Its thunks are exercised directly by unit tests;
the synthetic runtime fixture now calls them through a real PE IAT. Arbitrary PE
execution remains disabled, and `UnityPlayer.dll` and its dependencies are not
linked recursively.

FLS currently models one implicit fiber per guest thread context, with a
host-thread fallback only when no guest context is installed. Fiber switching
and process-wide callback enumeration are still pending, so the FLS surface is
classified as partial even though its symbols are available.

Completing the launcher's KERNEL32 surface, recursive DLL loading, complete API
Set contract mapping, PE TLS, and exception/unwind support are the next loader
milestones. See
[ROADMAP.md](ROADMAP.md) for the ordered compatibility plan and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component boundaries.

## Build

Requirements: x86-64 Linux, a GCC/Clang-compatible C11 compiler, GNU Make, and
POSIX threads.

```sh
make
make test
```

Useful commands:

```sh
./build/sadlayer inspect /path/to/game.exe
./build/sadlayer imports /path/to/UnityPlayer.dll
./build/sadlayer resolve-export /path/to/UnityPlayer.dll UnityMain2
./build/sadlayer link-check /path/to/hollow_knight.exe /path/to/UnityPlayer.dll
./build/sadlayer map /path/to/game.exe
./build/sadlayer run /path/to/game.exe
make sanitize
```

In a container or debugger where LeakSanitizer cannot attach, use
`make sanitize-no-leaks`; address and undefined-behavior checks remain enabled.

`map` now reserves the image at its real execution address and applies final PE
page protections. The isolated GS/TEB worker is intentionally restricted to
repository fixtures; `run` still stops before calling arbitrary guest code
until the remaining launcher imports and recursive dependency binding exist.
Its exit code is `3`, which makes automation distinguish “valid but not
runnable yet” from malformed input.

`link-check` registers the supplied PE DLL and SadLayer's built-in KERNEL32,
reports which executable imports it can resolve, and binds the IAT only when
every import is available. It does not recursively bind the supplied library's
own imports; in particular, resolving the launcher does not mean UnityPlayer's
522 imports are ready. Resolution is an address-level result, not a claim of
complete behavioral conformance for every thunk. An incomplete check never
leaves a partially modified image.

## First Hollow Knight probe

Point `inspect` at the Windows game executable and `imports` at its runtime DLL.
Do not commit the game or any proprietary DLL. These reports establish the exact
architecture and API surface of the build being targeted:

```sh
./build/sadlayer inspect "/path/to/Hollow Knight.exe"
./build/sadlayer imports "/path/to/UnityPlayer.dll"
```

The currently profiled target is documented in
[docs/HOLLOW_KNIGHT_TARGET.md](docs/HOLLOW_KNIGHT_TARGET.md).

## Principles

- Clean-room implementation based on public format and API documentation.
- Small milestones with a reproducible executable or test at every step.
- No game-specific binary patches in the loader.
- Diagnostics are part of the compatibility API: missing modules and symbols
  must be observable rather than becoming unexplained crashes.
- Hollow Knight is the initial acceptance target, not an excuse to hard-code a
  single machine or installation.

## License

[MIT](LICENSE)
