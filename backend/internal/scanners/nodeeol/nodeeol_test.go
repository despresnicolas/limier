package nodeeol

import (
	"reflect"
	"testing"
	"time"

	"limier/internal/scanners/source"
)

var now = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

func TestAnalyze(t *testing.T) {
	cases := []struct {
		dir  string
		want []source.Issue
	}{
		{"eol", []source.Issue{
			{Rule: Rule, Severity: source.High, File: ".nvmrc", Line: 1, Detail: "Node 16 · EOL 2023-09-11"},
			{Rule: Rule, Severity: source.High, File: "package.json", Line: 5, Detail: "Node 14 · EOL 2023-04-30"},
		}},
		{"soon", []source.Issue{{Rule: Rule, Severity: source.Medium, File: ".node-version", Line: 1, Detail: "Node 20 · EOL 2026-04-30"}}},
		{"current", nil},
		{"range", []source.Issue{{Rule: Rule, Severity: source.High, File: "package.json", Line: 4, Detail: "Node 18 · EOL 2025-04-30"}}},
		{"alias", nil},
		{"none", nil},
	}
	for _, c := range cases {
		if got := Analyze("testdata/"+c.dir, now); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.dir, got, c.want)
		}
	}
}

func TestLowestMajor(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{">=16", 16, true},
		{"^18.0.0", 18, true},
		{"18.x", 18, true},
		{"~20.11", 20, true},
		{"v22", 22, true},
		{"16 - 20", 16, true},
		{"^14.17.0 || >=16", 14, true},
		{">=20 || 18.x", 18, true},
		{"<22.5 >=18", 18, true},
		{"<20", 0, false},
		{"*", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		if got, ok := LowestMajor(c.in); got != c.want || ok != c.ok {
			t.Errorf("LowestMajor(%q) = %d, %v; want %d, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestPinnedMajor(t *testing.T) {
	cases := map[string]int{"v16.20.2": 16, "18": 18, " lts/Hydrogen ": 18, "node/22.1.0": 22}
	for in, want := range cases {
		if got, ok := pinnedMajor(in); !ok || got != want {
			t.Errorf("pinnedMajor(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"lts/*", "node", "stable", "system", "lts/unknown", ""} {
		if _, ok := pinnedMajor(in); ok {
			t.Errorf("pinnedMajor(%q) should be ignored", in)
		}
	}
}
