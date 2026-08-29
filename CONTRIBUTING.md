# Contributing

Start with an issue that names one observable compatibility gap and its smallest
reproduction. Changes should include a test or trace demonstrating the behavior.

Before submitting:

```sh
make check
make sanitize
```

Use public documentation and independently written tests. Do not copy code from
Wine, Proton, Windows, leaked sources, or proprietary game binaries. Do not
commit Hollow Knight files, Microsoft DLLs, SDK redistributables, crash dumps
containing proprietary code, or extracted game assets.

Keep platform backends separate from Windows-facing semantics, return explicit
errors for unsupported behavior, and preserve warnings-as-errors.

