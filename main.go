package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"
)

type config struct {
	ProtocolVersion string `json:"protocol_version"`
	ScanLevel       string `json:"scan_level"`
	ScanMode        string `json:"scan_mode"`
	DB              string `json:"db"`
	DBLastModified  string `json:"db_last_modified"`
}

type frame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
}

type finding struct {
	OSV   string  `json:"osv"`
	Trace []frame `json:"trace"`
}

type osvEntry struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		EcosystemSpecific struct {
			Imports []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

type message struct {
	Config  *config   `json:"config"`
	OSV     *osvEntry `json:"osv"`
	Finding *finding  `json:"finding"`
}

type key struct{ module, id string }
type observation struct {
	Module   bool            `json:"module"`
	Package  bool            `json:"package"`
	Symbol   bool            `json:"symbol"`
	Version  string          `json:"-"`
	Packages map[string]bool `json:"-"`
}
type scan struct {
	Config   config
	Findings map[key]*observation
	OSVs     map[string]osvEntry
}

type evidence struct {
	Module  bool `json:"module"`
	Package bool `json:"package"`
	Symbol  bool `json:"symbol"`
}
type result struct {
	ID       string   `json:"id"`
	Module   string   `json:"module"`
	Version  string   `json:"version,omitempty"`
	Status   string   `json:"status"`
	Scope    string   `json:"scope"`
	Evidence evidence `json:"evidence"`
	Summary  string   `json:"summary,omitempty"`
	Aliases  []string `json:"aliases,omitempty"`
	Reason   string   `json:"reason"`
}
type report struct {
	Binary             string       `json:"binary,omitempty"`
	GoFunctionTable    symbolInfo   `json:"go_function_table"`
	GovulncheckSymbols symbolAccess `json:"govulncheck_symbols"`
	DB                 string       `json:"db,omitempty"`
	DBLastModified     string       `json:"db_last_modified,omitempty"`
	Results            []result     `json:"results"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "govulndiff:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("govulndiff", flag.ContinueOnError)
	var format string
	fs.StringVar(&format, "format", "table", "output format: table or json")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: govulndiff [-format table|json] BINARY")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("provide exactly one binary path")
	}
	if format != "table" && format != "json" {
		return fmt.Errorf("invalid format %q", format)
	}
	binary := fs.Arg(0)
	levels := []string{"module", "package", "symbol"}
	scans := make([]scan, 3)
	for i, level := range levels {
		data, err := invoke(binary, level)
		if err != nil {
			return fmt.Errorf("%s scan: %w", level, err)
		}
		scans[i], err = parse(data, level)
		if err != nil {
			return fmt.Errorf("%s scan: %w", level, err)
		}
	}
	r, err := compare(scans[0], scans[1], scans[2])
	if err != nil {
		return err
	}
	r.Binary = binary
	r.GoFunctionTable = inspectSymbols(binary)
	r.GovulncheckSymbols = inspectSymbolAccess(binary)
	constrainBySymbolAccess(&r)
	if format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	return writeTable(out, r)
}

func invoke(binary, level string) ([]byte, error) {
	args := []string{"-mode=binary", "-scan=" + level, "-format=json", binary}
	cmd := exec.Command("govulncheck", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("govulncheck failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func parse(data []byte, expected string) (scan, error) {
	s := scan{Findings: make(map[key]*observation), OSVs: make(map[string]osvEntry)}
	dec := json.NewDecoder(bytes.NewReader(data))
	seenConfig := false
	for {
		var m message
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return s, fmt.Errorf("invalid JSON stream: %w", err)
		}
		if !seenConfig {
			if m.Config == nil {
				return s, errors.New("first message must be config")
			}
			if m.Config.ProtocolVersion == "" {
				return s, errors.New("missing protocol version")
			}
			if m.Config.ScanLevel != expected {
				return s, fmt.Errorf("scan level is %q, expected %q", m.Config.ScanLevel, expected)
			}
			if m.Config.ScanMode != "" && m.Config.ScanMode != "binary" {
				return s, fmt.Errorf("scan mode is %q, expected binary", m.Config.ScanMode)
			}
			s.Config = *m.Config
			seenConfig = true
			continue
		}
		if m.Config != nil {
			return s, errors.New("duplicate config message")
		}
		if m.OSV != nil {
			if m.OSV.ID == "" {
				return s, errors.New("OSV entry has no ID")
			}
			s.OSVs[m.OSV.ID] = *m.OSV
		}
		if m.Finding != nil {
			f := m.Finding
			if f.OSV == "" || len(f.Trace) == 0 || f.Trace[0].Module == "" {
				return s, errors.New("finding lacks OSV ID or module trace")
			}
			first := f.Trace[0]
			k := key{first.Module, f.OSV}
			o := s.Findings[k]
			if o == nil {
				o = &observation{Packages: make(map[string]bool)}
				s.Findings[k] = o
			}
			if o.Version != "" && first.Version != "" && o.Version != first.Version {
				return s, fmt.Errorf("conflicting versions for %s: %s and %s", k.module, o.Version, first.Version)
			}
			if first.Version != "" {
				o.Version = first.Version
			}
			switch {
			case first.Function != "" || first.Receiver != "":
				o.Symbol = true
				if first.Package != "" {
					o.Packages[first.Package] = true
				}
			case first.Package != "":
				o.Package = true
				o.Packages[first.Package] = true
			default:
				o.Module = true
			}
		}
	}
	if !seenConfig {
		return s, errors.New("empty JSON stream")
	}
	return s, nil
}

func compare(mod, pkg, sym scan) (report, error) {
	r := report{GoFunctionTable: symbolInfo{Status: "unknown", Detail: "no binary was provided for inspection"}, GovulncheckSymbols: symbolAccess{Status: "unknown", Detail: "no binary was provided for inspection"}, DB: mod.Config.DB, DBLastModified: mod.Config.DBLastModified, Results: []result{}}
	detailObserved := false
	for k := range mod.Findings {
		for _, o := range []*observation{pkg.Findings[k], sym.Findings[k]} {
			if o != nil && (o.Package || o.Symbol) {
				detailObserved = true
				break
			}
		}
		if detailObserved {
			break
		}
	}
	for _, s := range []scan{pkg, sym} {
		if mod.Config.DB != "" && s.Config.DB != "" && mod.Config.DB != s.Config.DB {
			return r, errors.New("scans use different vulnerability databases")
		}
		if mod.Config.DBLastModified != "" && s.Config.DBLastModified != "" && mod.Config.DBLastModified != s.Config.DBLastModified {
			return r, errors.New("scans use different database revisions")
		}
	}
	keys := make([]key, 0, len(mod.Findings))
	for k := range mod.Findings {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].module != keys[j].module {
			return keys[i].module < keys[j].module
		}
		return keys[i].id < keys[j].id
	})
	for _, k := range keys {
		m, p, s := mod.Findings[k], pkg.Findings[k], sym.Findings[k]
		if !m.Module {
			return r, fmt.Errorf("module scan has no module finding for %s", k.id)
		}
		for _, o := range []*observation{p, s} {
			if o != nil && m.Version != "" && o.Version != "" && m.Version != o.Version {
				return r, fmt.Errorf("module version differs between scans for %s in %s", k.id, k.module)
			}
		}
		entry, ok := sym.OSVs[k.id]
		if !ok {
			entry, ok = pkg.OSVs[k.id]
		}
		if !ok {
			entry, ok = mod.OSVs[k.id]
		}
		row := result{ID: k.id, Module: k.module, Version: m.Version, Evidence: evidence{Module: true}}
		if p != nil {
			row.Evidence.Package = p.Package || p.Symbol
		}
		if s != nil {
			row.Evidence.Package = row.Evidence.Package || s.Package || s.Symbol
			row.Evidence.Symbol = s.Symbol
		}
		if !ok {
			row.Scope, row.Status, row.Reason = "unknown", "undetermined", "OSV metadata is missing; cannot determine the advisory's detection scope"
		} else {
			row.Summary, row.Aliases = entry.Summary, entry.Aliases
			row.Scope, row.Status, row.Reason = classify(entry, k.module, p, s)
			if !detailObserved && row.Status == "not_affected" {
				row.Status, row.Reason = "undetermined", "neither detailed scan produced package or symbol findings; symbol information may be unavailable"
			}
		}
		r.Results = append(r.Results, row)
	}
	return r, nil
}

func classify(entry osvEntry, module string, p, s *observation) (scope, status, reason string) {
	matched := false
	hasImports, hasSymbols, hasPackageOnly := false, false, false
	packageOnlyPaths := make(map[string]bool)
	for _, a := range entry.Affected {
		if a.Package.Name != module {
			continue
		}
		matched = true
		for _, imp := range a.EcosystemSpecific.Imports {
			hasImports = true
			if len(imp.Symbols) > 0 {
				hasSymbols = true
			} else {
				hasPackageOnly = true
				packageOnlyPaths[imp.Path] = true
			}
		}
	}
	if !matched {
		return "unknown", "undetermined", "OSV metadata does not describe this module"
	}
	if !hasImports {
		return "module", "affected", "advisory has no package or symbol restrictions"
	}
	if hasSymbols && hasPackageOnly {
		scope = "mixed"
	} else if hasSymbols {
		scope = "symbol"
	} else {
		scope = "package"
	}
	if s != nil && s.Symbol {
		return scope, "affected", "symbol-level finding present"
	}
	if hasPackageOnly && p != nil {
		for path := range p.Packages {
			if packageOnlyPaths[path] {
				return scope, "affected", "affected package without symbol restrictions is present"
			}
		}
	}
	if scope == "package" {
		return scope, "not_affected", "no affected package found in package scan"
	}
	if scope == "mixed" {
		return scope, "not_affected", "no affected unrestricted package or vulnerable symbol found"
	}
	return scope, "not_affected", "no vulnerable symbol found in symbol scan"
}

func constrainBySymbolAccess(r *report) {
	if r.GovulncheckSymbols.Status != "not_found" {
		return
	}
	for i := range r.Results {
		row := &r.Results[i]
		if row.Scope == "module" || row.Scope == "unknown" {
			continue
		}
		row.Status = "undetermined"
		row.Evidence.Package = false
		row.Evidence.Symbol = false
		row.Reason = "linker symbols are missing; govulncheck may emit package and function findings as a module-level fallback"
	}
}

func writeTable(out io.Writer, r report) error {
	w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintf(w, "GOVULNCHECK SYMBOL INPUT\t%s", r.GovulncheckSymbols.Status); err != nil {
		return err
	}
	if r.GovulncheckSymbols.Detail != "" {
		if _, err := fmt.Fprintf(w, " — %s", r.GovulncheckSymbols.Detail); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "GO RUNTIME FUNCTION TABLE\t%s", r.GoFunctionTable.Status); err != nil {
		return err
	}
	if r.GoFunctionTable.FunctionCount > 0 {
		if _, err := fmt.Fprintf(w, " (%d function names)", r.GoFunctionTable.FunctionCount); err != nil {
			return err
		}
	}
	if r.GoFunctionTable.Detail != "" {
		if _, err := fmt.Fprintf(w, " — %s", r.GoFunctionTable.Detail); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "MODULE\tVERSION\tVULNERABILITY\tSCOPE\tEVIDENCE\tSTATUS"); err != nil {
		return err
	}
	for _, x := range r.Results {
		version := x.Version
		if version == "" {
			version = "-"
		}
		e := "M"
		if x.Evidence.Package {
			e += "/P"
		}
		if x.Evidence.Symbol {
			e += "/S"
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", x.Module, version, x.ID, x.Scope, e, x.Status); err != nil {
			return err
		}
	}
	return w.Flush()
}
