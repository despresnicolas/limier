package scanners

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNormalizeSeverity(t *testing.T) {
	tests := map[string]string{
		"CRITICAL": "critical", "High": "high", " moderate ": "medium", "MEDIUM": "medium",
		"Negligible": "low", "LOW": "low", "ERROR": "high", "WARNING": "medium", "INFO": "low",
		"": "unknown", "UNKNOWN": "unknown", "bogus": "unknown", "7.5": "high", "9.8": "critical",
	}
	for in, want := range tests {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{10, "critical"}, {9.0, "critical"}, {8.9, "high"}, {7.0, "high"},
		{6.9, "medium"}, {4.0, "medium"}, {3.9, "low"}, {0.1, "low"}, {0, "unknown"}, {-1, "unknown"},
	}
	for _, tt := range tests {
		if got := SeverityFromScore(tt.score); got != tt.want {
			t.Errorf("SeverityFromScore(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestCVSS3BaseScore(t *testing.T) {
	tests := []struct {
		vector  string
		want    float64
		wantErr bool
	}{
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", want: 9.8},
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", want: 10.0},
		{vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", want: 5.5},
		{vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", want: 4.2},
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", want: 7.5},
		{vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:H", want: 7.1},
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", want: 6.1},
		{vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", want: 6.4},
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", want: 0},
		// temporal metrics are ignored
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O", want: 9.8},
		{vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", wantErr: true},
		{vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", wantErr: true},
		{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", wantErr: true},
		{vector: "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", wantErr: true},
		{vector: "garbage", wantErr: true},
		{vector: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := CVSS3BaseScore(tt.vector)
		if (err != nil) != tt.wantErr {
			t.Errorf("CVSS3BaseScore(%q) err = %v, wantErr %v", tt.vector, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("CVSS3BaseScore(%q) = %v, want %v", tt.vector, got, tt.want)
		}
	}
}

func TestParseOSVVuln(t *testing.T) {
	v, err := ParseOSVVuln(fixture(t, "osv_ghsa.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "GHSA-gwrp-pvrq-jmwv" || v.Summary == "" || len(v.Affected) != 2 || len(v.References) != 2 {
		t.Fatalf("unexpected record: %+v", v)
	}
	if v.Published.Year() != 2022 || v.Modified.Year() != 2024 {
		t.Errorf("dates: %v %v", v.Published, v.Modified)
	}
	if v.Affected[0].Package.Purl != "pkg:npm/json5" || v.Affected[0].DatabaseSpecific["source"] == nil {
		t.Errorf("affected[0]: %+v", v.Affected[0])
	}
	if got := v.CVEs(); !reflect.DeepEqual(got, []string{"CVE-2022-46175"}) {
		t.Errorf("CVEs = %v", got)
	}
	score, vec, ok := v.CVSS()
	if !ok || score != 7.1 || vec != "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:H" {
		t.Errorf("CVSS = %v %q %v", score, vec, ok)
	}

	fixes := []struct{ eco, name, installed, want string }{
		{"npm", "json5", "1.0.1", "1.0.2"},
		{"npm", "json5", "2.2.1", "2.2.2"},
		{"NPM", "json5", "2.0.0", "2.2.2"},
		{"npm", "json5", "2.2.2", ""},
		{"npm", "json5", "1.5.0", ""}, // between ranges: not affected
		{"npm", "JSON5", "2.2.1", ""}, // name is case-sensitive
		{"PyPI", "json5", "2.2.1", ""},
		{"npm", "json5", "not-a-version", "1.0.2"}, // fallback to first fixed
	}
	for _, f := range fixes {
		if got := v.MinFixedVersion(f.eco, f.name, f.installed); got != f.want {
			t.Errorf("MinFixedVersion(%s,%s,%s) = %q, want %q", f.eco, f.name, f.installed, got, f.want)
		}
	}
}

func TestOSVFallbacks(t *testing.T) {
	v, err := ParseOSVVuln(fixture(t, "osv_no_cvss.json"))
	if err != nil {
		t.Fatal(err)
	}
	score, vec, ok := v.CVSS()
	if !ok || score != 5.5 || vec != "" {
		t.Errorf("CVSS fallback = %v %q %v", score, vec, ok)
	}
	if got := v.CVEs(); !reflect.DeepEqual(got, []string{"CVE-2020-28500"}) {
		t.Errorf("CVEs = %v", got)
	}
	if v.Modified.IsZero() {
		t.Error("fractional timestamp not parsed")
	}
	if got := v.MinFixedVersion("npm", "lodash", "4.17.20"); got != "4.17.21" {
		t.Errorf("ECOSYSTEM range fix = %q", got)
	}

	empty, _ := ParseOSVVuln([]byte(`{"id":"X-1"}`))
	if _, _, ok := empty.CVSS(); ok {
		t.Error("expected no CVSS")
	}
}

func TestMinFixedVersionEdgeCases(t *testing.T) {
	v, err := ParseOSVVuln([]byte(`{
	  "id": "TEST-1",
	  "affected": [
	    {"package": {"ecosystem": "npm", "name": "@scope/pkg"},
	     "ranges": [
	       {"type": "GIT", "repo": "https://x", "events": [{"introduced": "0"}, {"fixed": "abcdef"}]},
	       {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}, {"introduced": "1.5.0"}, {"fixed": "1.6.2"}]},
	       {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.3.5"}]},
	       {"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"last_affected": "3.2.0"}]}
	     ]}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ installed, want string }{
		{"1.2.0", "1.3.5"}, // smallest fix across overlapping ranges
		{"1.3.9", "1.4.0"},
		{"1.4.5", ""},
		{"1.5.0", "1.6.2"},
		{"3.1.0", ""}, // affected but no fix
		{"3.2.1", ""},
		{"0.9.0", ""},
	}
	for _, tt := range tests {
		if got := v.MinFixedVersion("npm", "@scope/pkg", tt.installed); got != tt.want {
			t.Errorf("MinFixedVersion(%s) = %q, want %q", tt.installed, got, tt.want)
		}
	}
}

func TestParseManifest(t *testing.T) {
	m, err := ParseManifest(fixture(t, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "web" || m.PackageManager != "pnpm@9.12.1" || len(m.Dependencies) != 2 || m.DevDependencies["typescript"] != "~5.4.0" {
		t.Errorf("manifest: %+v", m)
	}
	if !reflect.DeepEqual(m.Workspaces, []string{"packages/*", "apps/*"}) {
		t.Errorf("workspaces object form: %v", m.Workspaces)
	}
	if m.Overrides["semver"] != "^7.5.2" || m.PnpmOverrides["ws@<8.17.1"] != ">=8.17.1" || m.Resolutions["**/minimist"] != "1.2.8" {
		t.Errorf("overrides: %v %v %v", m.Overrides, m.PnpmOverrides, m.Resolutions)
	}
	arr, err := ParseManifest([]byte(`{"name": "x", "workspaces": ["a/*"], "dependencies": {"ok": "1.0.0", "bad": 5}}`))
	if err != nil || !reflect.DeepEqual(arr.Workspaces, []string{"a/*"}) || len(arr.Dependencies) != 1 {
		t.Errorf("array form: %+v %v", arr, err)
	}
}

func TestDirectDeps(t *testing.T) {
	root, _ := ParseManifest(fixture(t, "package.json"))
	got := DirectDeps(root)
	want := map[string]bool{"express": false, "@nestjs/core": false, "jest": true, "typescript": true, "fsevents": false, "rxjs": false}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("single = %v", got)
	}
	ws := Manifest{Dependencies: map[string]string{"jest": "29"}, DevDependencies: map[string]string{"eslint": "9"}}
	got = DirectDeps(root, ws)
	if got["jest"] || !got["eslint"] || !got["typescript"] {
		t.Errorf("merged = %v", got)
	}
	// order independence
	if got2 := DirectDeps(ws, root); !reflect.DeepEqual(got, got2) {
		t.Errorf("order dependent: %v vs %v", got, got2)
	}
}

func TestNpmLockPaths(t *testing.T) {
	got, err := NpmLockPaths(fixture(t, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"express@4.18.2":     {"express"},
		"body-parser@1.20.1": {"express", "body-parser"},
		"qs@6.11.0":          {"express", "qs"},
		"side-channel@1.0.4": {"express", "qs", "side-channel"},
		"debug@2.6.9":        {"express", "debug"},
		"ms@2.0.0":           {"express", "debug", "ms"},
		"jest@29.7.0":        {"jest"},
		"jest-cli@29.7.0":    {"jest", "jest-cli"},
		"debug@4.3.4":        {"jest", "jest-cli", "debug"},
		"ms@2.1.2":           {"jest", "jest-cli", "debug", "ms"},
		"@acme/shared@0.1.0": {"@acme/shared"},
		"@types/qs@6.9.11":   {"@types/qs"}, // direct dep of the workspace
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}

	v1, err := NpmLockPaths(fixture(t, "package-lock-v1.json"))
	wantV1 := map[string][]string{
		"debug@4.3.4": {"debug"},
		"send@0.18.0": {"send"},
		"ms@2.1.2":    {"debug", "ms"},
		"ms@2.1.3":    {"send", "ms"}, // nested copy wins over the hoisted one
	}
	if err != nil || !reflect.DeepEqual(v1, wantV1) {
		t.Errorf("v1: got %v %v\nwant %v", v1, err, wantV1)
	}
}

// Every parser must tolerate unexpected shapes and only fail on invalid JSON.
func TestParsersTolerance(t *testing.T) {
	parsers := map[string]func([]byte) error{
		"osv":      func(b []byte) error { _, err := ParseOSVVuln(b); return err },
		"manifest": func(b []byte) error { _, err := ParseManifest(b); return err },
		"npmlock":  func(b []byte) error { _, err := NpmLockPaths(b); return err },
	}
	odd := []string{
		`{}`, `[]`, `null`, `42`, `"str"`,
		`{"results": "x", "packages": 3, "Results": [{"Vulnerabilities": "nope"}], "matches": [1, null]}`,
		`{"modules": [{"source": 1, "dependencies": [{"resolved": null, "cycle": "x"}]}], "issues": [{"exports": "x"}]}`,
		`[{"Name": 3, "Code": "12", "RuleID": [], "Secret": 1234567}]`,
		`{"affected": [{"package": "npm", "ranges": [{"events": [{"introduced": 0}]}]}], "severity": "HIGH", "aliases": "CVE-1"}`,
		`{"components": [{"licenses": "MIT", "components": {"a": 1}}], "dependencies": [{"ref": 1}]}`,
		`{"packages": {"": {"dependencies": ["a"]}, "node_modules/a": "x"}}`,
	}
	for name, parse := range parsers {
		for _, in := range odd {
			if err := parse([]byte(in)); err != nil {
				t.Errorf("%s(%s): unexpected error %v", name, in, err)
			}
		}
		if err := parse([]byte(`{not json`)); err == nil {
			t.Errorf("%s: expected error on invalid JSON", name)
		}
	}
}
