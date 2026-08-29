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
- register mapped PE and native modules and resolve mixed forwarder chains;
- bind PE32/PE32+ import address tables without partial writes;
- expose an initial 54-export `KERNEL32.dll` subset through x86-64 `ms_abi`
  thunks for last-error state, time/identity, heap, TLS, no-fiber FLS, critical
  sections, text conversion, process strings, locale basics, standard streams,
  pointer encoding, and process termination;
- create explicit guest process objects with an OS-random pointer cookie used by
  the reversible `EncodePointer`/`DecodePointer` pair;
- convert explicit-length UTF-8/UTF-16 strictly or with replacement, without
  exposing Linux `wchar_t` at the Windows boundary;
- install nestable per-thread runtime contexts and route last-error/thread
  identity through them;
- classify the first Win32 DLL targets needed by the runtime;
- reject malformed and unsupported images with explicit errors.

The native KERNEL32 surface is a host-backed bootstrap subset, not a complete
Windows process environment. Its thunks are exercised directly by unit tests;
no PE entry point calls them yet. PE images are still allocation-backed and
non-executable, and `UnityPlayer.dll` and its dependencies are not linked
recursively.

FLS currently models one implicit fiber per host thread. Fiber switching and
process-wide callback enumeration are still pending, so the FLS surface is
classified as partial even though its symbols are available.

Executable address-stable mappings, recursive DLL loading, API Sets, PE TLS,
PEB/TEB state, exception/unwind support, and guarded guest execution are the next
loader milestones. See [ROADMAP.md](ROADMAP.md) for the ordered compatibility
plan and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component boundaries.

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

`run` deliberately stops after validating and mapping the image until the
execution handoff milestone is implemented. Its exit code is `3` in that case,
which makes automation distinguish “valid but not runnable yet” from malformed
input.

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
