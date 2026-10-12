# govulndiff

`govulndiff` is a proof of concept for giving module-only scanners the **`not_affected` information they are missing**. It compares govulncheck results for a binary at module, package, and symbol levels, then reports every module-level vulnerability—including explicit `not_affected` results when the more specific checks rule it out. A scanner that sees only module versions can use those results to avoid reporting a vulnerability already assessed as not affecting that binary.

## Install and run

Requires Go and `govulncheck` on `PATH` ([installation instructions](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)).

```sh
go build -o govulndiff .
./govulndiff ./my-program
./govulndiff -format json ./my-program > assessment.json
```

Pass one Go binary path. The tool runs `govulncheck` from `PATH` three times, at module, package, and symbol levels. Govulncheck makes requests to the [Go Vulnerability Database at vuln.go.dev](https://go.dev/doc/security/vuln/database) for vulnerability data; this tool does not download or manage a database. The records use the **OSV data format**, which does not mean govulncheck queries the osv.dev website. A scan failure stops the comparison.

## Extract a binary from an image

The optional `scripts/extract.sh` helper uses `skopeo` to copy a Linux amd64 image and extract one file. It always writes under this repository's `extracted/` directory, keeping the path from the image:

```sh
./scripts/extract.sh example.com/my-image:latest /usr/local/bin/my-program
# Output: extracted/usr/local/bin/my-program
./govulndiff ./extracted/usr/local/bin/my-program
```

## Reading the report

A **module** is a dependency, a **package** is a part of that dependency, and a **symbol** is a function or method in a package. Each row covers one known vulnerability in one module.

The two lines above the table answer different questions:

| Field | Meaning |
| --- | --- |
| `GOVULNCHECK SYMBOL INPUT` | Whether the binary has the linker symbol govulncheck needs to analyze packages and functions. `present` means it is available; `not_found` means it is missing. JSON: `govulncheck_symbols.status`. |
| `GO RUNTIME FUNCTION TABLE` | Whether a separate Go runtime table of function names can be read. JSON: `go_function_table.status` and `go_function_table.function_count`. This count includes normal runtime functions, **not** just vulnerable functions. |

Either field can be `unknown` if the binary format could not be inspected.

Go's `-ldflags='-s -w'` removes the normal linker symbol table and DWARF debug data, but can leave the Go runtime function table (`pclntab`) in place. A stripped binary can therefore show **`GOVULNCHECK SYMBOL INPUT: not_found` and `GO RUNTIME FUNCTION TABLE: present` at the same time**. Govulncheck cannot use the remaining runtime table alone for a reliable package or function assessment. Some govulncheck versions still emit package and function findings as a conservative fallback for stripped binaries; this tool labels such rows `undetermined` and shows only module evidence.

`SCOPE` comes from the vulnerability record that govulncheck read from its database—normally **vuln.go.dev**. Specifically, this tool reads the record's affected package and function details from govulncheck's JSON output. It tells you how specifically the database describes the vulnerability; it does not describe what was found in the binary:

| Value | Meaning |
| --- | --- |
| `module` | The vulnerability is described for the whole module. |
| `package` | It is tied to one or more packages, with no specific functions named. |
| `symbol` | It is tied to specific functions or methods. |
| `mixed` | Some affected packages have named functions; others do not. |
| `unknown` | The vulnerability details were missing or could not be matched to the module. |

`EVIDENCE` comes from govulncheck's findings for **this binary**, not from the database's vulnerability description. It tells you what the scans found in the binary:

| Code | Meaning |
| --- | --- |
| `M` | The binary uses a module version with this known vulnerability. Every row starts here. |
| `P` | The scan also found an affected package from that module in the binary. |
| `S` | The scan also found a vulnerable function or method in the binary. |

The letters build on each other: `M/P` means the module and an affected package were found, but no vulnerable function was found. `M/P/S` means a vulnerable function was found too. `P` alone does **not** mean the binary is affected when `SCOPE` is `symbol`.

`STATUS` is the assessment to use:

| Value | Meaning |
| --- | --- |
| `affected` | The scan found enough detail to match the vulnerability, or the vulnerability applies to the whole module. |
| `not_affected` | The module version has the vulnerability, but the detailed scans did not find the affected package or function in this binary. A module-only scanner can omit this finding for this binary. |
| `undetermined` | The scans did not provide enough information for a safe answer. |

Example:

```text
GOVULNCHECK SYMBOL INPUT  present
GO RUNTIME FUNCTION TABLE  present (1234 function names)

MODULE            VERSION  VULNERABILITY  SCOPE   EVIDENCE  STATUS
example.com/lib   v1.0.0   GO-2026-0001   symbol  M/P       not_affected
example.com/lib   v1.0.0   GO-2026-0002   symbol  M/P/S     affected
```

In the first row, the binary contains the package, but the scan did not find the vulnerable function. The second row includes the vulnerable function.

JSON contains the same rows under `results`, with `id`, `module`, `version`, `status`, `scope`, `evidence`, `summary`, `aliases`, and `reason`. The top level also includes `govulncheck_symbols`, `go_function_table`, the binary path, database URL, and database revision when available. Rows are sorted by module and vulnerability ID. An empty `results` array means the module scan found no vulnerable modules.

The module scan defines which module and vulnerability pairs appear in the report. If a detailed scan attributes a finding to a different module that has no matching module-level finding, that extra finding is ignored; it cannot change another module's assessment.

`not_affected` means govulncheck found no affected package or symbol **in this binary under this scan**. It is an assessment of the binary, not a claim that the module version itself has no vulnerability. Binary analysis cannot prove call reachability, so a symbol finding means that vulnerable code is present and could be used.

Govulncheck can fall back to module-level assessment when it cannot extract linker symbols from a binary, even when its output contains package or function findings. If linker symbols are missing, this tool uses `undetermined` for package- and symbol-scoped vulnerabilities. It also uses `undetermined` if both detailed scans produce only module findings.

Govulncheck's [JSON protocol](https://pkg.go.dev/golang.org/x/vuln/internal/govulncheck) and [binary scanning behavior](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) define the input semantics.
