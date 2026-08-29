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
- translate RVAs to file offsets;
- map headers and sections into an in-memory image;
- classify the first Win32 DLL targets needed by the runtime;
- reject malformed and unsupported images with explicit errors.

Import symbol binding, relocations, TLS, Win32 calls, and guest execution are the
next stages. See [ROADMAP.md](ROADMAP.md) for the ordered compatibility plan and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component boundaries.

## Build

Requirements: a C11 compiler and GNU Make.

```sh
make
make test
```

Useful commands:

```sh
./build/sadlayer inspect /path/to/game.exe
./build/sadlayer imports /path/to/UnityPlayer.dll
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
