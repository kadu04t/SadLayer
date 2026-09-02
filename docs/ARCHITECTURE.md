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
  bounded mixed PE/native forwarder chain. This provides the routing primitive
  for API Set contracts but does not read `ApiSetSchema`, select a host by
  version, or populate target-specific mappings.
- `unicode`: validates and converts explicit-length UTF-8/UTF-16 buffers without
  using the incompatible Linux `wchar_t` representation.
- `process`: owns stable per-guest process state: an OS-random pointer cookie,
  minimal PEB, and normalized process-parameters storage. Handles, address-space
  ownership, and loader state will move behind the same lifecycle.
- `context`: installs a nestable thread-local view of the active Windows thread
  and process object; last-error, thread identity, TLS/FLS values, and pointer
  encoding already use it. An atomic ownership token prevents one guest context
  from running on two host threads simultaneously. Contexts retain the process
  while active, so process destruction occurs only after all guest workers,
  TEBs, and active scopes have exited.
- `teb`: allocates two writable TEB pages between guard pages and materializes
  the launcher-observed stack, identity, PEB, and last-error offsets. The PE TLS
  vector remains null until the loader owns module TLS. The isolated runtime
  worker installs the TEB base in GS only around guest execution and verifies
  restoration before releasing it.
- `kernel32`: provides the first host-backed x86-64 `ms_abi` thunks. Current
  coverage is a bootstrap subset backed by the minimal PEB/TEB layouts, but it
  does not yet constitute a complete object, filesystem, or exception runtime.
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
  reporting and publishing its single wire record.

Public headers live under `include/sadlayer`; implementations live under `src`.
Tests construct redistributable PE-shaped fixtures in memory.

## Boundaries to preserve

1. Parsing does not mutate or trust the guest image.
2. Mapping does not resolve APIs or start execution.
3. The module registry resolves symbols to process addresses. Native modules are
   responsible for exact `ms_abi` signatures and fixed-width Windows types;
   validated guest-pointer access remains a separate runtime boundary.
4. Windows object handles are SadLayer-managed identifiers, not leaked Linux file
   descriptors or pointers.
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
