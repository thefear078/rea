# Paranoia provider

[Paranoia](https://github.com/Altumptic/paranoia) is an Apache-2.0 reverse-engineering engine written in Rust, distributed as one `paranoia` executable. REA uses a `paranoia` you supply. It does not download, install, update or bundle Paranoia.

Paranoia is static: it reads the selected image and never executes it. REA drives it through `paranoia query`, which prints one JSON answer in the `paranoia-query/1` format per run ([format reference](https://github.com/Altumptic/paranoia/blob/main/docs/QUERY.md)).

## Configure

```bash
export REA_PARANOIA_COMMAND=/absolute/path/to/paranoia
rea doctor --provider paranoia
```

Select it explicitly with `--provider paranoia`, MCP's `open_binary.provider_id: "paranoia"`, or `REA_ANALYSIS_PROVIDER=paranoia`. With Paranoia and another provider configured for the same target, `auto` reports `ambiguous` instead of choosing one.

| Setting                   | Default         | Meaning                                                      |
| ------------------------- | --------------- | ------------------------------------------------------------ |
| `REA_PARANOIA_COMMAND`    | none (required) | Absolute path of the `paranoia` executable.                  |
| `REA_PARANOIA_TIMEOUT_MS` | 120 s           | Deadline for one `paranoia query` run (analysis and answer). |

Targets: PE, ELF and thin Mach-O executables for x86, x86-64, AArch64, ARM, RISC-V, MIPS and PowerPC. Universal Mach-O files, archives and databases are rejected with a typed reason. `rea doctor --provider paranoia` checks the configuration, runs `paranoia --version` and hashes the executable.

## What Paranoia answers

| Tool                                                        | Source                                                                                                            |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `list_procedures`, `search_procedures`, `procedure_address` | The inventory's functions (entry points, symbols, exports, unwind tables, Go's function table, recursive descent) |
| `address_name`                                              | Function and import names by exact address                                                                        |
| `list_strings`, `search_strings`                            | Mapped ASCII and UTF-16LE strings from the inventory                                                              |
| `procedure_callers`, `procedure_callees`                    | The inventory's direct call edges; callees include import slots                                                   |
| `procedure_pseudo_code`, `procedure_assembly`               | `paranoia query function`; pseudocode is null on architectures without a decompiler                               |
| `xrefs`                                                     | `paranoia query xrefs`: code and data references to the exact address                                             |

Typed references, basic blocks, raw-memory tools, annotations, `analyze_function` and type recovery are not available from this provider.

## How answers are produced

The first query of a session runs `paranoia query TARGET inventory` and keeps the validated inventory for the session; listings, searches, names, callers and callees come from it. Pseudocode, assembly, references and interior-address lookups run `paranoia query TARGET function|xrefs SEL` each time. Every run is a separate process under REA's owned-process supervision, with the deadline above and a 256 MiB output cap; cancelling a request stops its run, and closing the session proves every run stopped.

Every answer carries the SHA-256 of the bytes Paranoia analysed. REA rejects an answer whose digest differs from the selected target's, so a file replaced after opening is reported instead of silently analysed. The analysis profile records Paranoia's version, the executable's SHA-256 and the query format; replacing the executable during a session is reported too, and needs a reopen.

## Verification

`tests/boundary/providers/paranoia/paranoiaProvider.test.ts` covers configuration, target support and address handling without a process. The same file has live tests that run when `REA_PARANOIA_COMMAND` and `REA_PARANOIA_TEST_TARGET` are set: every advertised operation against a real binary, the digest check, and a closed session.

Verified on Windows 11 with Paranoia 0.7.0 (`paranoia query` from main) and REA's packaged Windows native module: the live tests pass on `notepad.exe` (PE, x86-64), a stripped Go `gofmt` for linux/amd64 (ELF) and one for darwin/arm64 (Mach-O, AArch64). Not yet run on Linux or macOS hosts.
