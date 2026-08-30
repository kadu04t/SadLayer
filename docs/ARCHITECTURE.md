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
- `module`: owns normalized module names, borrows mapped PE images or static
  native export tables, and resolves name/ordinal symbols through bounded mixed
  PE/native forwarder chains.
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
  vector remains null until the loader owns module TLS. GS installation is
  intentionally deferred to the isolated dispatcher.
- `kernel32`: provides the first host-backed x86-64 `ms_abi` thunks. Current
  coverage is a bootstrap subset backed by the minimal PEB/TEB layouts, but it
  does not yet constitute a complete object, filesystem, or exception runtime.
- `win32`: defines the x86-64 calling-convention marker and identifies planned
  bootstrap module names.
- CLI: owns files, prints target inventory, and exposes individual loader gates.
- `runtime`: exposes an explicitly caller-trusted direct AMD64 handoff. The
  repository uses it only for its static fixture, and the CLI never exposes it
  for arbitrary PE input; guarded worker execution remains pending.

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

The direct runtime handoff relies on its caller to establish trust. SadLayer's
own caller is restricted to the repository's static fixture, while the CLI
keeps arbitrary handoff disabled. It has real executable permissions and ABI
transitions but no signal containment, guest stack, or GS restoration yet.

FLS currently treats each guest thread context as one implicit fiber, with a
host-thread-local fallback only outside a guest context. Its values are not yet
enumerated process-wide during `FlsFree`, and no fiber switch can move the
active FLS state. This is an explicitly partial compatibility surface until the
guest fiber model exists.
