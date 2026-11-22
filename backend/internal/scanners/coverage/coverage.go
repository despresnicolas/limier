// Package coverage reports the test coverage of a project without running anything (SPECS F3.9):
// it reads the report the project's own tools left on disk (istanbul/c8/vitest/jest), and always
// estimates which source files at least one test reaches through the import graph.
package coverage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"limier/internal/scanners/imports"
	"limier/internal/scanners/source"
)

// Metric is covered/total of one kind (lines, branches…).
type Metric struct {
	Covered int     `json:"covered"`
	Total   int     `json:"total"`
	Pct     float64 `json:"pct"`
}

func (m *Metric) add(covered, total int) {
	m.Covered += covered
	m.Total += total
}

func (m *Metric) finish() {
	m.Pct = 0
	if m.Total > 0 {
		m.Pct = float64(int(float64(m.Covered)*1000/float64(m.Total))) / 10
	}
}

// File is the line coverage of one source file of a report.
type File struct {
	File  string `json:"file"`
	Lines Metric `json:"lines"`
}

// Measured is a coverage report found in the project. Statements is nil for lcov, which has none.
type Measured struct {
	Format     string    `json:"format"` // "istanbul-summary", "lcov" or "istanbul"
	Reports    []string  `json:"reports"`
	Date       time.Time `json:"date"` // newest report: tests may have changed since
	Lines      Metric    `json:"lines"`
	Statements *Metric   `json:"statements,omitempty"`
	Functions  Metric    `json:"functions"`
	Branches   Metric    `json:"branches"`
	Files      []File    `json:"files"` // least covered first, capped at MaxFiles
}

// Estimate is the share of source files that at least one test imports, directly or not.
type Estimate struct {
	TestFiles   int      `json:"test_files"`
	SourceFiles int      `json:"source_files"`
	Reached     int      `json:"reached"`
	Pct         float64  `json:"pct"`
	Untested    []string `json:"untested"` // capped at MaxFiles
}

type Report struct {
	Measured *Measured `json:"measured,omitempty"`
	Estimate Estimate  `json:"estimate"`
}

const (
	MaxFiles      = 300
	maxReportSize = 50 << 20
)

// Analyze reads the coverage report under root, if any, and estimates the test reach from the graph.
func Analyze(root string, files []source.File, graph imports.Report) Report {
	return Report{Measured: Read(root), Estimate: Reach(files, graph)}
}

// reportDirs are where the coverage folder of the root or of a workspace usually is.
// shortcut: only coverage/ at the root and one or two folders deep (packages/x, apps/x); read a configured reportsDirectory if users ask.
var reportDirs = []string{"coverage", "*/coverage", "*/*/coverage"}

// Read finds coverage reports (summary JSON first, then lcov, then the full istanbul JSON) and merges them.
func Read(root string) *Measured {
	for _, f := range []struct {
		name, format string
		parse        func(root string, b []byte, m *Measured) bool
	}{
		{"coverage-summary.json", "istanbul-summary", parseSummary},
		{"lcov.info", "lcov", parseLcov},
		{"coverage-final.json", "istanbul", parseFinal},
	} {
		m := &Measured{Format: f.format, Files: []File{}}
		for _, dir := range reportDirs {
			matches, _ := filepath.Glob(filepath.Join(root, dir, f.name))
			for _, p := range matches {
				if strings.Contains(filepath.ToSlash(p), "/node_modules/") {
					continue
				}
				info, err := os.Lstat(p)
				if err != nil || !info.Mode().IsRegular() || info.Size() > maxReportSize {
					continue // never follow a symlink out of the project
				}
				b, err := os.ReadFile(p)
				if err != nil || !f.parse(root, b, m) {
					continue
				}
				rel, _ := filepath.Rel(root, p)
				m.Reports = append(m.Reports, filepath.ToSlash(rel))
				if info.ModTime().After(m.Date) {
					m.Date = info.ModTime()
				}
			}
		}
		if len(m.Reports) > 0 {
			return m.finish()
		}
	}
	return nil
}

func (m *Measured) finish() *Measured {
	m.Lines.finish()
	m.Functions.finish()
	m.Branches.finish()
	if m.Statements != nil {
		m.Statements.finish()
	}
	for i := range m.Files {
		m.Files[i].Lines.finish()
	}
	sort.Slice(m.Files, func(i, j int) bool {
		a, b := m.Files[i].Lines, m.Files[j].Lines
		if a.Pct != b.Pct {
			return a.Pct < b.Pct
		}
		return m.Files[i].File < m.Files[j].File
	})
	if len(m.Files) > MaxFiles {
		m.Files = m.Files[:MaxFiles]
	}
	return m
}

// relPath turns a report path (often absolute, possibly through a symlinked folder) into a project path.
func relPath(root, p string) string {
	p = filepath.FromSlash(p)
	if !filepath.IsAbs(p) {
		return filepath.ToSlash(filepath.Clean(p))
	}
	for _, r := range []string{root, evalOr(root)} {
		if rel, err := filepath.Rel(r, p); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(p)
}

func evalOr(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

type summaryEntry struct {
	Lines, Statements, Functions, Branches struct{ Total, Covered int }
}

// parseSummary reads istanbul's json-summary: {"total": {...}, "/abs/file.ts": {...}}.
func parseSummary(root string, b []byte, m *Measured) bool {
	var doc map[string]summaryEntry
	if json.Unmarshal(b, &doc) != nil {
		return false
	}
	total, ok := doc["total"]
	if !ok {
		return false
	}
	if m.Statements == nil {
		m.Statements = &Metric{}
	}
	m.Lines.add(total.Lines.Covered, total.Lines.Total)
	m.Statements.add(total.Statements.Covered, total.Statements.Total)
	m.Functions.add(total.Functions.Covered, total.Functions.Total)
	m.Branches.add(total.Branches.Covered, total.Branches.Total)
	for name, e := range doc {
		if name != "total" {
			m.Files = append(m.Files, File{File: relPath(root, name), Lines: Metric{Covered: e.Lines.Covered, Total: e.Lines.Total}})
		}
	}
	return true
}

// parseLcov reads lcov records: SF, LF/LH, FNF/FNH, BRF/BRH, end_of_record.
func parseLcov(root string, b []byte, m *Measured) bool {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var cur *File
	records := 0
	num := func(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }
	var fnf, fnh, brf, brh int
	for sc.Scan() {
		key, val, _ := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		switch key {
		case "SF":
			cur = &File{File: relPath(root, val)}
			fnf, fnh, brf, brh = 0, 0, 0, 0
		case "LF":
			if cur != nil {
				cur.Lines.Total = num(val)
			}
		case "LH":
			if cur != nil {
				cur.Lines.Covered = num(val)
			}
		case "FNF":
			fnf = num(val)
		case "FNH":
			fnh = num(val)
		case "BRF":
			brf = num(val)
		case "BRH":
			brh = num(val)
		case "end_of_record":
			if cur != nil {
				m.Lines.add(cur.Lines.Covered, cur.Lines.Total)
				m.Functions.add(fnh, fnf)
				m.Branches.add(brh, brf)
				m.Files = append(m.Files, *cur)
				records++
			}
			cur = nil
		}
	}
	return records > 0
}

type finalEntry struct {
	Path         string                         `json:"path"`
	StatementMap map[string]struct{ Start pos } `json:"statementMap"`
	S            map[string]int                 `json:"s"`
	F            map[string]int                 `json:"f"`
	B            map[string][]int               `json:"b"`
}

type pos struct{ Line int }

// parseFinal reads istanbul's coverage-final.json; a line is covered when one of its statements ran.
func parseFinal(root string, b []byte, m *Measured) bool {
	var doc map[string]finalEntry
	if json.Unmarshal(b, &doc) != nil || len(doc) == 0 {
		return false
	}
	if m.Statements == nil {
		m.Statements = &Metric{}
	}
	for key, e := range doc {
		name := e.Path
		if name == "" {
			name = key
		}
		lines := map[int]bool{}
		f := File{File: relPath(root, name)}
		for id, n := range e.S {
			m.Statements.add(b2i(n > 0), 1)
			if st, ok := e.StatementMap[id]; ok {
				lines[st.Start.Line] = lines[st.Start.Line] || n > 0
			}
		}
		for _, hit := range lines {
			f.Lines.add(b2i(hit), 1)
		}
		for _, n := range e.F {
			m.Functions.add(b2i(n > 0), 1)
		}
		for _, arms := range e.B {
			for _, n := range arms {
				m.Branches.add(b2i(n > 0), 1)
			}
		}
		m.Lines.add(f.Lines.Covered, f.Lines.Total)
		m.Files = append(m.Files, f)
	}
	return true
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

var (
	reTestBase   = regexp.MustCompile(`\.(test|spec)\.[cm]?[jt]sx?$`)
	reNotSource  = regexp.MustCompile(`(^|/)[^/]*\.(config|stories|story)\.[^/]+$|(^|/)\.[^/]+$|\.d\.ts$`)
	testDirNames = map[string]bool{"__tests__": true, "test": true, "tests": true, "e2e": true, "cypress": true, "playwright": true, "__mocks__": true}
)

// IsTest reports whether a path is a test file (or a helper living in a test folder).
func IsTest(p string) bool {
	if reTestBase.MatchString(path.Base(p)) {
		return true
	}
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if testDirNames[seg] {
			return true
		}
	}
	return false
}

// Reach counts the source files that a test imports, following runtime imports only
// (a type-only import runs no code). Config, stories, scripts and .d.ts files are not sources.
// shortcut: reached is not executed, a file imported by a test may still have untested lines; the measured report says that.
func Reach(files []source.File, graph imports.Report) Estimate {
	isSource := map[string]bool{}
	var tests []string
	for _, f := range files {
		switch {
		case !f.IsCode():
		case IsTest(f.Path):
			tests = append(tests, f.Path)
		case !reNotSource.MatchString(f.Path) && !strings.HasPrefix(f.Path, "scripts/") && !strings.Contains(f.Path, "/scripts/"):
			isSource[f.Path] = true
		}
	}
	next := map[string][]string{}
	for _, e := range graph.Edges {
		if !e.TypeOnly {
			next[e.From] = append(next[e.From], e.To)
		}
	}
	seen := map[string]bool{}
	queue := append([]string{}, tests...)
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if seen[n] {
			continue
		}
		seen[n] = true
		queue = append(queue, next[n]...)
	}
	est := Estimate{TestFiles: len(tests), SourceFiles: len(isSource), Untested: []string{}}
	for p := range isSource {
		if seen[p] {
			est.Reached++
		} else {
			est.Untested = append(est.Untested, p)
		}
	}
	sort.Strings(est.Untested)
	if len(est.Untested) > MaxFiles {
		est.Untested = est.Untested[:MaxFiles]
	}
	if est.SourceFiles > 0 {
		est.Pct = float64(est.Reached*1000/est.SourceFiles) / 10
	}
	return est
}
