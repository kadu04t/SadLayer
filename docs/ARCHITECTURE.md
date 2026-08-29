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
- `loader`: creates the zero-filled virtual image and copies PE headers/sections
  to their RVAs, applies base relocations, and atomically binds resolved imports.
  Executable mappings and final memory protections belong here next.
- `module`: tracks borrowed mapped images, resolves exports without regard to DLL
  name casing, and follows bounded export-forwarder chains.
- `win32`: identifies bootstrap module names. Implementations of built-in DLLs
  will live below this boundary.
- CLI: owns files, prints target inventory, and exposes individual loader gates.

Public headers live under `include/sadlayer`; implementations live under `src`.
Tests construct redistributable PE-shaped fixtures in memory.

## Boundaries to preserve

1. Parsing does not mutate or trust the guest image.
2. Mapping does not resolve APIs or start execution.
3. The module registry resolves a Windows symbol to a typed ABI thunk; platform
   backends never receive raw guest pointers without validation.
4. Windows object handles are SadLayer-managed identifiers, not leaked Linux file
   descriptors or pointers.
5. UTF-16 and Windows path semantics terminate at the NT layer; backends receive
   normalized internal values.
6. Every unsupported API is attributable by module, symbol, caller, and chosen
   fallback. This trace is the primary driver for compatibility work.

## Security model

PE files and all guest pointers are untrusted input. Integer overflow, range,
termination, access, and lifetime checks are mandatory at the boundary. The
runtime is not initially a security sandbox, so only trusted game binaries should
be executed. Process isolation and syscall restriction come after functional
process bootstrap but before recommending general third-party binaries.
