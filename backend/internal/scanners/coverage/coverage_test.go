package coverage

import (
	"path/filepath"
	"reflect"
	"testing"

	"limier/internal/scanners/imports"
	"limier/internal/scanners/source"
)

func TestSummary(t *testing.T) {
	m := Read(filepath.Join("testdata", "summary"))
	if m == nil || m.Format != "istanbul-summary" || m.Date.IsZero() {
		t.Fatalf("summary: %+v", m)
	}
	if m.Lines != (Metric{8, 10, 80}) || *m.Statements != (Metric{9, 12, 75}) || m.Functions.Pct != 50 || m.Branches.Pct != 50 {
		t.Errorf("totals: %+v %+v", m, m.Statements)
	}
	// Least covered first; absolute paths outside the root stay as they are.
	want := []File{{"src/mail.ts", Metric{2, 4, 50}}, {"/somewhere/app/src/price.ts", Metric{6, 6, 100}}}
	if !reflect.DeepEqual(m.Files, want) || !reflect.DeepEqual(m.Reports, []string{"coverage/coverage-summary.json"}) {
		t.Errorf("files: %+v reports %v", m.Files, m.Reports)
	}
}

func TestLcov(t *testing.T) {
	m := Read(filepath.Join("testdata", "lcov"))
	if m == nil || m.Format != "lcov" || m.Statements != nil {
		t.Fatalf("lcov: %+v", m)
	}
	if m.Lines != (Metric{3, 6, 50}) || m.Functions != (Metric{1, 3, 33.3}) || m.Branches != (Metric{1, 2, 50}) {
		t.Errorf("totals: %+v", m)
	}
	if m.Files[0].File != "src/b.ts" || m.Files[0].Lines.Pct != 0 {
		t.Errorf("files: %+v", m.Files)
	}
}

func TestFinal(t *testing.T) {
	m := Read(filepath.Join("testdata", "final"))
	if m == nil || m.Format != "istanbul" {
		t.Fatalf("final: %+v", m)
	}
	// Line 1 has one statement that ran, line 3 none.
	if m.Lines != (Metric{1, 2, 50}) || *m.Statements != (Metric{1, 3, 33.3}) || m.Functions != (Metric{1, 1, 100}) || m.Branches != (Metric{1, 2, 50}) {
		t.Errorf("totals: %+v %+v", m, *m.Statements)
	}
}

func TestNoReport(t *testing.T) {
	if m := Read(t.TempDir()); m != nil {
		t.Errorf("want nil, got %+v", m)
	}
}

func TestReach(t *testing.T) {
	files, err := source.Walk(filepath.Join("testdata", "summary"))
	if err != nil {
		t.Fatal(err)
	}
	e := Reach(files, imports.Analyze(files))
	// price.ts and math.ts run under the test; types.ts is only a type import; config files are not sources.
	want := Estimate{TestFiles: 1, SourceFiles: 4, Reached: 2, Pct: 50, Untested: []string{"src/mail.ts", "src/types.ts"}}
	if !reflect.DeepEqual(e, want) {
		t.Errorf("got %+v\nwant %+v", e, want)
	}
}
