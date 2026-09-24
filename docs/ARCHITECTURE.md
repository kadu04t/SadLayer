# Architecture

SadLayer is a userspace compatibility layer, not a virtual machine. On matching
x86-64 hosts, Windows guest instructions execute on the CPU while SadLayer owns
the Windows binary loader and API boundary. Linux-native code implements the
observable contracts expected by the guest.

```text
Windows EXE and DLLs
        |
        v
PE loader ---- module registry ---- built-in Win32 DLL exports
        |                                  |
        v                                  v
guest x86-64 entry point            NT/process object model
                                           |
                       +-------------------+-------------------+
                       |                   |                   |
                  Linux files/VM     window/input       graphics/audio
                                                          backends
```

## Current components

- `pe`: immutable, bounds-checked views of PE metadata. It never takes ownership
  of the file buffer and never executes guest data.
- `loader`: retains a heap-backed staging path for inspection and link analysis,
  plus an execution path that reserves a non-destructive `mmap`, relocates to
  its actual address, atomically binds imports, and seals page-unioned PE
  permissions while rejecting writable/executable pages.
- `module`: owns bounded copied module names plus up to 128 explicit,
  case-insensitive, one-hop aliases to already registered modules; alias chains
  are rejected. It borrows mapped PE images or static native export tables and
  applies the same alias-aware lookup to imports/IAT binding and every step of a
  bounded mixed PE/native forwarder chain. Exact-handle lookup treats a PE's
  mapping base as its `HMODULE`, and address lookup uses the mapped image's
  half-open interval; neither aliases nor native built-ins receive handles.
  This provides the routing primitive for API Set contracts but does not read
  `ApiSetSchema`, select a host by version, or populate target-specific
  mappings.
- `module_space`: is the first ownership layer above the registry. It copies
  each explicitly supplied PE file, parses and maps it into stable per-entry
  storage, and publishes the borrowed registry pointers only after the entire
  addition succeeds. Callers receive a read-only registry view; native-module
  and alias registration, PE import binding, and final protection changes go
  through the owning space, which permits finalization only after a successful
  binding pass. Destruction unmaps owned images in reverse order. It does not
  yet search for dependencies, bind the graph as a transaction, run
  TLS/`DllMain`, or unload individual modules. A process may adopt exactly one
  fully bound and finalized space; after that transfer, external code receives
  only an immutable view and process destruction owns its cleanup.
- `unicode`: validates and converts explicit-length UTF-8/UTF-16 buffers without
  using the incompatible Linux `wchar_t` representation.
- `handle_table`: owns 256 typed object slots per guest process. Handles are
  opaque tagged generation/slot tokens, never Linux descriptors or host
  pointers. `FILE` and `SEARCH` kinds cannot be confused; acquiring a handle
  creates a reference-counted lease, close invalidates its token immediately,
  and object destruction is deferred until existing leases end without running
  callbacks under the table lock. A clone-safe atomic snapshot protocol keeps
  the table coherent across the isolated worker's `clone`, rejecting active
  leases or destructors, while process teardown drains still-open objects after
  guest operations are quiescent. `CloseHandle` dispatches only `FILE` tokens
  into this core; `SEARCH` remains reserved for `FindClose`, and no guest file
  creation API is connected yet.
- `process`: owns stable per-guest process state: an OS-random pointer cookie,
  typed handle table, three atomic standard-handle slots, minimal PEB, and
  normalized process-parameters storage. Standard-handle values are isolated
  between processes but remain raw, non-owning values until file objects are
  connected. Before any thread or worker retains it, a one-shot operation can
  transfer in one finalized module space, designate its exact main PE, and copy
  a validated UTF-16 image path supplied with an explicit length into
  process-owned terminated storage. The same operation writes the main mapping
  base to `PEB.ImageBaseAddress`; later manual image-base changes cannot
  contradict the adopted main module.
  It also owns the atomically replaceable top-level exception filter used by
  explicit guest exception dispatch.
  Module-space, main-module, and path getters are borrowed read-only views valid
  for the retained process lifetime. Guest-facing handle APIs and recursive
  loader state remain future work.
- `context`: installs a nestable thread-local view of the active Windows thread
  and process object; last-error, thread identity, TLS/FLS values, and pointer
  encoding already use it. An atomic ownership token prevents one guest context
  from running on two host threads simultaneously. Contexts retain the process
  while active, so process destruction occurs only after all guest workers,
  TEBs, and active scopes have exited.
- `teb`: allocates two writable TEB pages between guard pages and materializes
  the launcher-observed stack, identity, PEB, and last-error offsets. The PE TLS
  vector remains null until the loader owns module TLS. Trusted host-side stack
  bounds accompany the guest-visible NT_TIB values so unwind code never trusts
  writable guest metadata while dereferencing frames. The isolated runtime
  worker installs the TEB base in GS only around guest execution and verifies
  restoration before releasing it.
- `kernel32`: provides the first host-backed x86-64 `ms_abi` thunks. Current
  coverage is a 68-export bootstrap subset backed by the minimal PEB/TEB
  layouts. Module queries resolve only inside the installed process context.
  `GetModuleHandleW` and `GetModuleHandleExW` expose the main image or
  registered PE basenames; the latter can also identify a module by an address
  in its half-open mapped range. Supported pin/reference-count flags are
  observational no-ops while the adopted module space keeps every module
  resident. `GetProcAddress` accepts exact export names or ordinals from a PE
  `HMODULE`, treats a null handle as the main image, and follows registry-backed
  forwarders. `RtlPcToFileHeader` maps a program counter back to its owning PE
  image. `LoadLibraryExW` is deliberately catalog-only: it accepts the default
  request and the launcher's measured System32-search flag, then reacquires an
  already adopted PE basename. `FreeLibrary` validates that process-local
  handle but leaves its mapping resident. Path-bearing names are rejected until
  the catalog owns canonical paths for every DLL.
  `GetModuleFileNameW` returns the process-owned main-image path and implements
  modern null-terminated truncation. Native built-ins intentionally have no
  `HMODULE`; disk discovery, reference counts, unload, and `DllMain` remain
  outside this facade. `GetStdHandle`, `SetStdHandle`, and `GetStartupInfoW`
  read the installed process's isolated slots; only the fixed bootstrap tokens
  currently identify host console streams, so assigning an arbitrary future
  file handle cannot accidentally redirect it to `stdout`. `CloseHandle`
  invalidates process-local `FILE` tokens, rejects stale or wrong-kind values,
  and intentionally does not clear standard-handle slots that reference a
  closed token. Seven exception exports connect explicit raises,
  process-local unhandled filtering, function lookup, virtual unwind, and
  second-pass unwind/context restoration to the static PE unwind engine. The
  subset does not yet constitute a complete loader, object, filesystem, or
  general exception runtime.
- `win64_unwind`: defines byte-exact AMD64 Windows exception/context layouts,
  captures and restores CPU context through assembly gateways, validates
  immutable PE exception directories, and transactionally interprets version-1
  and version-2 unwind records. It supports chained records, prologue and
  declared-epilogue states, saved nonvolatile integer/XMM registers, machine
  frames, first-pass exception handlers, and second-pass termination handlers.
  A protected host-side handler link lets a guest handler call `RtlUnwindEx`
  without exposing SadLayer's SysV frames to the Windows unwinder. Dynamic/JIT
  function tables, signals translated into SEH, nested/collided or exit unwind,
  history caching, and special consolidate/long-jump restore semantics remain
  outside this component.
- `win32`: defines the x86-64 calling-convention marker and identifies planned
  bootstrap module names.
- CLI: owns files, prints target inventory, and exposes individual loader gates.
- `runtime`: retains a low-level direct AMD64 fixture hook and adds a synchronous
  bootstrap worker created without shared VM state. The worker starts on a
  guard-paged stack, creates and attaches its own thread context/TEB, installs
  GS, normalizes inherited signal dispositions/masks, calls the trusted PE
  entry, and restores GS. Returns, internal failures, and handled fatal signals
  use a versioned fixed-width wire record. The crash handler runs on its own 128
  KiB guard-paged signal stack and captures the signal/code, fault address, RIP,
  and even a destroyed RSP using direct Linux AMD64 syscalls. `ExitProcess` and
  `TerminateProcess` become `EXITED` outcomes through `waitpid`, with exit codes
  temporarily limited to eight bits; unhandled signals become `SIGNALLED`
  outcomes through the same wait path. The CLI does not expose either handoff to
  arbitrary PE input. Normal completion blocks signals before disarming crash
  reporting and publishing its single wire record. The higher-level
  `sl_runtime_run_process_main` path derives both image descriptors from the
  process-owned main module, while legacy entry points reject an unrelated
  image once a process has adopted its module space.

Public headers live under `include/sadlayer`; implementations live under `src`.
Tests construct redistributable PE-shaped fixtures in memory.

## Boundaries to preserve

1. Parsing does not mutate or trust the guest image.
2. Mapping does not resolve APIs or start execution.
3. The module registry resolves symbols to process addresses. Native modules are
   responsible for exact `ms_abi` signatures and fixed-width Windows types;
   validated guest-pointer access remains a separate runtime boundary.
4. Windows object handles are SadLayer-managed identifiers, not leaked Linux
   file descriptors or pointers. `HMODULE` is the deliberate PE exception: it
   is the image's mapped base, matching the guest-visible loader identity.
5. UTF-16 and Windows path semantics terminate at the NT layer; backends receive
   normalized internal values.
6. Every unsupported API is attributable by module, symbol, caller, and chosen
   fallback. This trace is the primary driver for compatibility work.
7. The guest dispatcher installs a process/thread scope before the first native
   thunk call. APIs without a Windows error channel fail fast if this internal
   lifecycle invariant is broken.

## Security model

PE files and all guest pointers are untrusted input. Integer overflow, range,
termination, access, and lifetime checks are mandatory at the boundary. The
runtime is not initially a security sandbox, so only trusted game binaries should
be executed. Process isolation and syscall restriction come after functional
process bootstrap but before recommending general third-party binaries.

Current KERNEL32 unit tests pass trusted host buffers directly to thunks. Guest
address-range and access validation are not complete, so these functions are not
yet a safe boundary for executing untrusted PE code.

Both runtime handoffs rely on the caller to establish trust. The worker isolates
address-space writes and fatal guest signals from the parent, blocks signals
across `clone`, resets inherited catchable dispositions, installs its crash
handlers, clears the child signal mask, uses guard pages, and emits fixed crash
context from an alternate stack. The parent signal state is restored immediately
after `clone`. The worker is not a sandbox: it still inherits file descriptors
and syscall access, has no timeout, and starts from a single-threaded host
snapshot with a default, waitable `SIGCHLD` disposition. The CLI therefore keeps
arbitrary handoff disabled.

FLS currently treats each guest thread context as one implicit fiber, with a
host-thread-local fallback only outside a guest context. Its values are not yet
enumerated process-wide during `FlsFree`, and no fiber switch can move the
active FLS state. This is an explicitly partial compatibility surface until the
guest fiber model exists.
