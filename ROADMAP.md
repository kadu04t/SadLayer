# Roadmap to Hollow Knight

The north-star test is the Windows build of Hollow Knight reaching its title
screen, accepting keyboard/controller input, rendering correctly, and playing
audio on an x86-64 Linux host. “Launch” is split into observable gates so each
failure identifies the next subsystem instead of hiding behind one binary goal.

Dates are intentionally omitted. Completion is based on exit criteria and test
artifacts, not estimates made before the target binary has been profiled.

## Stage 0 — Bootstrap and target inventory (complete for profiled build)

Deliverables:

- C11 project with dependency-free build and sanitizer-friendly tests;
- bounds-checked PE32/PE32+ parsing, RVA translation, import discovery, and
  section mapping;
- `inspect`, `map`, and staged `run` commands;
- a local, non-redistributed inventory of the target EXE/DLL architecture,
  imports, PE features, and runtime logs.

Exit gate: `sadlayer inspect` and `sadlayer map` succeed on the target executable
without sanitizer findings. The inventory is recorded as metadata without
shipping proprietary files.

This gate is satisfied for the hashes recorded in
`docs/HOLLOW_KNIGHT_TARGET.md`.

## Stage 1 — Correct PE loader and process bootstrap

Implement, in order:

- [x] Base relocations for PE32/PE32+ images.
- [x] Import enumeration by name and ordinal.
- [x] Export lookup by name and ordinal, including forwarded exports.
- [x] Case-insensitive module registry and forwarder traversal.
- [x] Native module registration and mixed PE/native export forwarding.
- [x] Atomic IAT binding for PE32 and PE32+.
- [x] Initial x86-64 `ms_abi` thunk declarations and direct ABI smoke tests.
- [x] Address-stable executable mappings with relocation fallback and final
  page-granular PE protections under a W^X policy.
- [x] Controlled `ms_abi` handoff for a trusted synthetic PE that calls two
  built-in KERNEL32 exports through its real IAT and returns to the host.
- [ ] Isolated subprocess worker on a guarded guest stack with GS/TEB
  installation and restoration around the synthetic handoff.
- [ ] Alternate signal stack and fixed-format crash reporting that survives a
  destroyed guest stack and leaves the parent runtime usable.
- [ ] Recursive DLL discovery, delay imports, and API Set contracts.
- [ ] PE TLS directory, callbacks, and per-module thread data.
- [ ] Structured tracing for module load, symbol resolution, calls, and last
  error.

Exit gate: a synthetic Windows fixture calls a built-in `kernel32` function from
its real entry point and returns the expected code to the host.

The direct-call portion of this gate is satisfied. It is not yet the guarded
worker required before accepting arbitrary PE input.

## Stage 2 — NT and kernel32 foundation

Implement the minimum coherent process model rather than isolated stubs:

- [x] Initial host-backed KERNEL32 subset: last-error, identity/time, process
  heap, TLS and no-fiber FLS, critical sections, code-page queries and
  conversions, process strings, pointer encoding, basic locale
  classification/casing, standard streams, and process exit.
- [x] Explicit guest process object with an OS-random pointer cookie and
  reversible `EncodePointer`/`DecodePointer` behavior.
- [x] Validated explicit-length UTF-8/UTF-16 conversion primitives.
- [x] Nestable native thread context for last-error/thread identity and the
  future process object.
- [x] Minimal measured PEB, process-parameters, and guarded TEB memory layouts;
  KERNEL32 last-error aliases the TEB cell when attached.
- [ ] GS-backed TEB installation, guest stack, PE TLS directory/callbacks,
  validated guest pointers, and coherent handles/object lifetimes.
- [ ] Fiber contexts and process-wide FLS callback enumeration.
- [ ] Current directory, Windows path normalization, virtual memory, files,
  directories, mappings, waits, synchronization objects, and threads.
- [ ] Remaining launcher imports: dynamic module lookup, filesystem/search, and
  x64 exception/unwind APIs.
- [ ] Registry overlay stored inside a SadLayer prefix.

Exit gate: purpose-built PE conformance programs pass file, memory, threading,
TLS, timing, environment, and loader tests under SadLayer.

### Immediate blockers before a controlled Hollow Knight handoff

1. [x] Map PE images at their real process addresses with final page protections
   instead of treating `load_base` as metadata over `calloc`.
2. [ ] Install the prepared TEB/PEB through GS, switch to a guarded guest stack,
   and expose stack bounds and process parameters before guest code.
3. [ ] Move the passing synthetic PE entry-point fixture under guarded
   signal/crash tracing in an isolated worker.
4. [ ] Complete the launcher's remaining KERNEL32 imports through coherent module,
   handle/filesystem, and x64 exception/unwind subsystems.
5. [ ] Recursively load, relocate, and bind UnityPlayer and its dependency graph; the
   current link check only examines the executable.
6. [ ] Resolve API Set contracts and implement DLL initialization order, `DllMain`,
   PE TLS data, and TLS callbacks.

## Stage 3 — Unity/Mono startup surface

Hollow Knight builds may differ, so the Stage 0 inventory decides the precise
worklist. Expected families include:

- `ntdll`, `kernel32`, `advapi32`, `user32`, `gdi32`, `shell32`, `ole32`,
  `winmm`, and version/locale APIs;
- child DLL loading and native plugin discovery;
- enough window/message-loop, monitor, cursor, keyboard, and filesystem behavior
  for Unity initialization;
- crash reports containing the first unresolved symbol and guest stack context.

Exit gate: the target initializes its engine/runtime, creates a window, and
continues pumping messages without an unresolved bootstrap import.

## Stage 4 — Graphics

Start with the API selected by the actual target logs. The likely path is a
DXGI/D3D11 compatibility frontend backed by Vulkan, implemented as distinct
layers:

- DXGI adapters, outputs, swap chains, presentation, and resize/fullscreen;
- D3D11 resources, views, state objects, command submission, and synchronization;
- DXBC inspection and shader translation with a growing differential corpus;
- format/capability tables and explicit unsupported-feature diagnostics.

An SDL-like window helper may be used later, but the core ABI remains owned by
SadLayer. Third-party platform libraries require an explicit dependency review;
Wine/Proton code is not imported.

Exit gate: clear-color triangle, textured quad, and Unity startup render tests
pass before the game reaches a stable title screen at correct colors and aspect.

## Stage 5 — Audio and input

- XAudio2/legacy audio surface chosen from target imports, backed by PipeWire or
  ALSA;
- XInput controller state, vibration, and hotplug;
- Raw Input/keyboard/mouse mapping, focus, cursor capture, and layout behavior;
- deterministic input and audio smoke tests independent of the game.

Exit gate: title music is audible, keyboard and a controller navigate the menu,
and focus/fullscreen transitions do not lose input.

## Stage 6 — Playability and packaging

- save/config paths, locale, achievements boundary, and controller persistence;
- frame pacing, memory/performance profiling, shader cache, and startup cache;
- isolated prefixes, per-game configuration, logs, crash dumps, and a launcher;
- compatibility matrix covering distributions, GPU vendors, and multiple legal
  game builds supplied by testers.

Exit gate: start a new game, play through an initial gameplay checkpoint, save,
restart, and load it with stable rendering, sound, and input.

## Test strategy across every stage

- Unit tests for parsers, tables, path rules, and state machines.
- Tiny PE fixtures that exercise one Windows contract each.
- Golden traces for loader/module behavior.
- Fuzz every parser that consumes guest-controlled memory.
- Game probes record hashes and metadata only; proprietary binaries never enter
  the repository or CI.
- CI runs warnings-as-errors and AddressSanitizer/UndefinedBehaviorSanitizer.

## Explicit non-goals for the first playable milestone

- 32-bit guest execution, ARM hosts, macOS, anti-cheat, installers, .NET desktop,
  general Office application compatibility, and every DirectX generation.
- Bit-for-bit Windows behavior where Unity/Hollow Knight does not observe it.
- Pretending a stub is implemented: compatibility shims must return documented
  failures and emit a trace until their behavior is real.
