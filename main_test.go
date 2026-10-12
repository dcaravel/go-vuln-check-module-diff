package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func stream(t *testing.T, level string, messages ...any) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	if err := enc.Encode(map[string]any{"config": map[string]any{"protocol_version": "v1.0.0", "scan_level": level, "scan_mode": "binary", "db": "https://vuln.go.dev", "db_last_modified": "2026-10-01T00:00:00Z"}}); err != nil {
		t.Fatal(err)
	}
	for _, m := range messages {
		if err := enc.Encode(m); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func findingMessage(id, module, pkg, function string) any {
	return map[string]any{"finding": map[string]any{"osv": id, "trace": []any{map[string]any{"module": module, "version": "v1.0.0", "package": pkg, "function": function}}}}
}

func TestCompareKeepsNegativeModuleFindings(t *testing.T) {
	const module = "example.com/lib"
	osvs := []any{
		map[string]any{"osv": map[string]any{"id": "GO-1", "summary": "symbol vulnerability", "affected": []any{map[string]any{"package": map[string]any{"name": module}, "ecosystem_specific": map[string]any{"imports": []any{map[string]any{"path": module + "/x", "symbols": []string{"Bad"}}}}}}}},
		map[string]any{"osv": map[string]any{"id": "GO-2", "affected": []any{map[string]any{"package": map[string]any{"name": module}, "ecosystem_specific": map[string]any{"imports": []any{map[string]any{"path": module + "/y"}}}}}}},
		map[string]any{"osv": map[string]any{"id": "GO-3", "affected": []any{map[string]any{"package": map[string]any{"name": module}}}}},
	}
	moduleMessages := append([]any{}, osvs...)
	for _, id := range []string{"GO-1", "GO-2", "GO-3"} {
		moduleMessages = append(moduleMessages, findingMessage(id, module, "", ""))
	}
	packageMessages := append([]any{}, osvs...)
	packageMessages = append(packageMessages, findingMessage("GO-1", module, "", ""), findingMessage("GO-1", module, module+"/x", ""), findingMessage("GO-2", module, "", ""), findingMessage("GO-3", module, "", ""))
	symbolMessages := append([]any{}, osvs...)
	symbolMessages = append(symbolMessages, findingMessage("GO-1", module, "", ""), findingMessage("GO-1", module, module+"/x", ""), findingMessage("GO-2", module, "", ""), findingMessage("GO-3", module, "", ""))
	m, err := parse(stream(t, "module", moduleMessages...), "module")
	if err != nil {
		t.Fatal(err)
	}
	p, err := parse(stream(t, "package", packageMessages...), "package")
	if err != nil {
		t.Fatal(err)
	}
	s, err := parse(stream(t, "symbol", symbolMessages...), "symbol")
	if err != nil {
		t.Fatal(err)
	}
	r, err := compare(m, p, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Results) != 3 {
		t.Fatalf("got %d rows, want all three module findings", len(r.Results))
	}
	want := map[string]string{"GO-1": "not_affected", "GO-2": "not_affected", "GO-3": "affected"}
	for _, row := range r.Results {
		if row.Status != want[row.ID] {
			t.Errorf("%s: status %s, want %s", row.ID, row.Status, want[row.ID])
		}
	}
	var table bytes.Buffer
	if err := writeTable(&table, r); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(table.String(), "\n")
	headerFound := false
	for _, line := range lines {
		if strings.Join(strings.Fields(line), " ") == "MODULE VERSION VULNERABILITY SCOPE EVIDENCE STATUS" {
			headerFound = true
			break
		}
	}
	if !headerFound {
		t.Fatalf("scope and evidence columns should be adjacent: %s", table.String())
	}
	if strings.Count(table.String(), "not_affected") != 2 {
		t.Fatalf("negative rows missing from table:\n%s", table.String())
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `"status":"not_affected"`) != 2 {
		t.Fatalf("negative rows missing from JSON: %s", data)
	}
}

func TestSymbolFindingMakesModuleAffected(t *testing.T) {
	const module = "example.com/lib"
	osv := map[string]any{"osv": map[string]any{"id": "GO-1", "affected": []any{map[string]any{"package": map[string]any{"name": module}, "ecosystem_specific": map[string]any{"imports": []any{map[string]any{"path": module + "/x", "symbols": []string{"Bad"}}}}}}}}
	m, _ := parse(stream(t, "module", osv, findingMessage("GO-1", module, "", "")), "module")
	p, _ := parse(stream(t, "package", osv, findingMessage("GO-1", module, module+"/x", "")), "package")
	s, _ := parse(stream(t, "symbol", osv, findingMessage("GO-1", module, module+"/x", "Bad")), "symbol")
	r, err := compare(m, p, s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Results[0].Status != "affected" || !r.Results[0].Evidence.Symbol {
		t.Fatalf("unexpected result: %+v", r.Results[0])
	}
}

func TestCompareIgnoresDetailedFindingOutsideModuleScan(t *testing.T) {
	const module = "github.com/quay/claircore"
	const toolkit = module + "/toolkit"
	osv := map[string]any{"osv": map[string]any{"id": "GO-2026-5939", "affected": []any{map[string]any{"package": map[string]any{"name": module}, "ecosystem_specific": map[string]any{"imports": []any{map[string]any{"path": module + "/libindex", "symbols": []string{"Fetch"}}}}}}}}
	m, err := parse(stream(t, "module", osv, findingMessage("GO-2026-5939", module, "", "")), "module")
	if err != nil {
		t.Fatal(err)
	}
	p, err := parse(stream(t, "package", osv, findingMessage("GO-2026-5939", toolkit, toolkit+"/types", "")), "package")
	if err != nil {
		t.Fatal(err)
	}
	s, err := parse(stream(t, "symbol", osv, findingMessage("GO-2026-5939", toolkit, toolkit+"/types", "Fetch")), "symbol")
	if err != nil {
		t.Fatal(err)
	}
	r, err := compare(m, p, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Results) != 1 || r.Results[0].Module != module {
		t.Fatalf("unexpected report rows: %+v", r.Results)
	}
	if r.Results[0].Status != "undetermined" || r.Results[0].Evidence.Package || r.Results[0].Evidence.Symbol {
		t.Fatalf("unmatched detailed finding changed the module assessment: %+v", r.Results[0])
	}
}

func TestRejectDifferentDatabaseRevision(t *testing.T) {
	m, _ := parse(stream(t, "module"), "module")
	p, _ := parse(stream(t, "package"), "package")
	s, _ := parse(stream(t, "symbol"), "symbol")
	s.Config.DBLastModified = "2026-10-02T00:00:00Z"
	if _, err := compare(m, p, s); err == nil {
		t.Fatal("expected database revision mismatch")
	}
}

func TestRejectWrongScanLevel(t *testing.T) {
	if _, err := parse(stream(t, "module"), "symbol"); err == nil {
		t.Fatal("expected scan level validation error")
	}
}

func TestModuleOnlyDetailedScansAreUndetermined(t *testing.T) {
	const module = "example.com/lib"
	osv := map[string]any{"osv": map[string]any{"id": "GO-1", "affected": []any{map[string]any{"package": map[string]any{"name": module}, "ecosystem_specific": map[string]any{"imports": []any{map[string]any{"path": module + "/x", "symbols": []string{"Bad"}}}}}}}}
	m, _ := parse(stream(t, "module", osv, findingMessage("GO-1", module, "", "")), "module")
	p, _ := parse(stream(t, "package", osv, findingMessage("GO-1", module, "", "")), "package")
	s, _ := parse(stream(t, "symbol", osv, findingMessage("GO-1", module, "", "")), "symbol")
	r, err := compare(m, p, s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Results[0].Status != "undetermined" {
		t.Fatalf("unexpected result: %+v", r.Results[0])
	}
}

func TestRunRequiresBinary(t *testing.T) {
	var out bytes.Buffer
	if err := run(nil, &out); err == nil || !strings.Contains(err.Error(), "exactly one binary path") {
		t.Fatalf("expected binary requirement, got %v", err)
	}
	if err := run([]string{"first", "second"}, &out); err == nil || !strings.Contains(err.Error(), "exactly one binary path") {
		t.Fatalf("expected one-binary requirement, got %v", err)
	}
}

func TestInspectSymbolsWithAndWithoutLinkerStripping(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, stripped := range []bool{false, true} {
		output := filepath.Join(dir, "binary")
		args := []string{"build", "-o", output}
		if stripped {
			args = append(args, "-ldflags=-s -w")
		}
		args = append(args, source)
		cmd := exec.Command("go", args...)
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build: %v: %s", err, data)
		}
		info := inspectSymbols(output)
		if info.Status != "present" || info.FunctionCount == 0 {
			t.Fatalf("stripped=%t: %+v", stripped, info)
		}
		access := inspectSymbolAccess(output)
		want := "present"
		if stripped {
			want = "not_found"
		}
		if access.Status != want {
			t.Fatalf("stripped=%t: govulncheck access=%+v, want %s", stripped, access, want)
		}
	}
}

func TestMissingLinkerSymbolsDoNotCountAsDetailedEvidence(t *testing.T) {
	r := report{GovulncheckSymbols: symbolAccess{Status: "not_found"}, Results: []result{
		{ID: "GO-1", Scope: "symbol", Status: "affected", Evidence: evidence{Module: true, Package: true, Symbol: true}},
		{ID: "GO-2", Scope: "module", Status: "affected", Evidence: evidence{Module: true}},
	}}
	constrainBySymbolAccess(&r)
	if r.Results[0].Status != "undetermined" || r.Results[0].Evidence.Package || r.Results[0].Evidence.Symbol {
		t.Fatalf("fallback findings treated as detailed evidence: %+v", r.Results[0])
	}
	if r.Results[1].Status != "affected" {
		t.Fatalf("module-wide advisory changed: %+v", r.Results[1])
	}
}
