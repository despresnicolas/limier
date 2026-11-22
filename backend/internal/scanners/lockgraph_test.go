package scanners

import (
	"encoding/json"
	"reflect"
	"testing"
)

func viaOf(t *testing.T, g LockGraph, err error) map[string][]string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return g.Via()
}

func TestNpmLockGraphVia(t *testing.T) {
	g, err := NpmLockGraph(fixture(t, "package-lock.json"))
	got := viaOf(t, g, err)
	want := map[string][]string{
		"body-parser@1.20.1": {"express"},
		"qs@6.11.0":          {"express"},
		"side-channel@1.0.4": {"express"},
		"debug@2.6.9":        {"express"},
		"ms@2.0.0":           {"express"},
		"jest-cli@29.7.0":    {"jest"},
		"debug@4.3.4":        {"jest"},
		"ms@2.1.2":           {"jest"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	if !g.Direct["express@4.18.2"] || !g.Direct["@types/qs@6.9.11"] || g.Direct["@acme/shared@0.1.0"] {
		t.Errorf("direct: %v", g.Direct)
	}
}

func TestPnpmLockGraphVia(t *testing.T) {
	g, err := PnpmLockGraph(fixture(t, "pnpm-lock.yaml"))
	got := viaOf(t, g, err)
	want := map[string][]string{
		"svelte@5.1.0":     {"@sveltejs/kit"}, // also direct: the UI only shows via for transitive packages
		"acorn@8.12.0":     {"@sveltejs/kit", "svelte"},
		"cookie@0.6.0":     {"@sveltejs/kit"},
		"debug@4.3.4":      {"@sveltejs/kit"}, // direct of the ui workspace too
		"ms@2.1.2":         {"@sveltejs/kit", "debug"},
		"ansi-regex@5.0.1": {"strip-ansi"}, // alias "strip" resolves to strip-ansi
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	for _, d := range []string{"@sveltejs/kit@2.5.0", "svelte@5.1.0", "debug@4.3.4", "strip-ansi@6.0.1"} {
		if !g.Direct[d] {
			t.Errorf("%s not direct: %v", d, g.Direct)
		}
	}

	g6, err := PnpmLockGraph(fixture(t, "pnpm-lock-v6.yaml"))
	if got := viaOf(t, g6, err); !reflect.DeepEqual(got, map[string][]string{"debug@2.6.9": {"express"}, "ms@2.0.0": {"express"}}) {
		t.Errorf("v6: %v", got)
	}
}

func TestYarnLockGraphVia(t *testing.T) {
	m := Manifest{Dependencies: map[string]string{"express": "^4.18.2"}, DevDependencies: map[string]string{"@babel/core": "^7.0.0"}}
	g, err := YarnLockGraph(fixture(t, "yarn-v1.lock"), m)
	got := viaOf(t, g, err)
	want := map[string][]string{
		"@babel/helpers@7.24.0": {"@babel/core"},
		"debug@4.3.4":           {"@babel/core", "express"},
		"ms@2.1.2":              {"@babel/core", "express"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("v1 got  %v\nwant %v", got, want)
	}

	g, err = YarnLockGraph(fixture(t, "yarn-berry.lock"))
	got = viaOf(t, g, err)
	want = map[string][]string{"debug@4.3.4": {"express"}, "ms@2.1.2": {"debug", "express"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("berry got  %v\nwant %v", got, want)
	}
	if !g.Direct["debug@4.3.4"] || !g.Direct["express@4.18.2"] {
		t.Errorf("berry direct: %v", g.Direct)
	}
}

func TestBuildCycloneDX(t *testing.T) {
	g, err := NpmLockGraph(fixture(t, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := BuildCycloneDX(g)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Name, Version, Purl string
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(doc, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" || len(bom.Components) != len(g.Packages()) || len(bom.Components) == 0 {
		t.Fatalf("bom: %s", doc)
	}
	purls := map[string]bool{}
	for _, c := range bom.Components {
		purls[c.Purl] = true
	}
	if !purls["pkg:npm/%40types/qs@6.9.11"] || !purls["pkg:npm/express@4.18.2"] {
		t.Errorf("purls: %v", purls)
	}
	for _, d := range bom.Dependencies {
		if d.Ref == "pkg:npm/debug@2.6.9" && !reflect.DeepEqual(d.DependsOn, []string{"pkg:npm/ms@2.0.0"}) {
			t.Errorf("debug dependsOn %v", d.DependsOn)
		}
	}
}

func TestSplitLockID(t *testing.T) {
	for id, want := range map[string][2]string{"a@1.0.0": {"a", "1.0.0"}, "@s/b@2.0.0": {"@s/b", "2.0.0"},
		"g@git+ssh://git@github.com/a/g.git": {"g", "git+ssh://git@github.com/a/g.git"}} {
		if n, v := SplitLockID(id); n != want[0] || v != want[1] {
			t.Errorf("%s: %s %s", id, n, v)
		}
	}
}

func TestLockGraphRisks(t *testing.T) {
	npm := func(f string) (LockGraph, error) { return NpmLockGraph(fixture(t, f)) }
	pnpm := func(f string) (LockGraph, error) { return PnpmLockGraph(fixture(t, f)) }
	yarn := func(f string) (LockGraph, error) {
		m := Manifest{Dependencies: map[string]string{"clean": "^1.0.0", "gitdep": "github:acme/gitdep", "corp": "^2.0.0"}}
		return YarnLockGraph(fixture(t, f), m)
	}
	for _, tc := range []struct {
		file  string
		parse func(string) (LockGraph, error)
		want  map[string][]string
	}{
		{"risks-package-lock.json", npm, map[string][]string{
			"esbuild@0.20.2": {"install-script"},
			"gitdep@1.2.0":   {"git:git+ssh://github.com/acme/gitdep.git"},
			"plain@1.0.0":    {"http:http://mirror.example.com/plain/-/plain-1.0.0.tgz"},
			"corp@2.0.0":     {"registry:npm.corp.example"},
			"vendored@1.0.0": {"file:vendor/vendored-1.0.0.tgz"},
		}},
		{"risks-pnpm-lock.yaml", pnpm, map[string][]string{
			"esbuild@0.20.2": {"install-script"},
			"corp@2.0.0":     {"registry:npm.corp.example"},
			"vendored@file:vendor/vendored-1.0.0.tgz": {"file:vendor/vendored-1.0.0.tgz"},
			"gitdep@github.com/acme/gitdep/0123456":   {"git:https://codeload.github.com/acme/gitdep/tar.gz/0123456"},
		}},
		{"risks-pnpm-lock-v9.yaml", pnpm, map[string][]string{
			"gitdep@git+ssh://git@github.com/acme/gitdep.git#0123456": {"git:git+ssh://github.com/acme/gitdep.git"},
			"local@file:../local": {"file:../local"},
		}},
		{"risks-yarn-v1.lock", yarn, map[string][]string{
			"gitdep@1.2.0": {"git:https://codeload.github.com/acme/gitdep/tar.gz/0123456"},
			"corp@2.0.0":   {"registry:npm.corp.example"},
		}},
		{"risks-yarn-berry.lock", yarn, map[string][]string{
			"gitdep@1.2.0":         {"git:https://github.com/acme/gitdep.git"},
			"@acme/vendored@1.0.0": {"file:./vendor/v.tgz#./vendor/v.tgz"},
		}},
	} {
		g, err := tc.parse(tc.file)
		if err != nil {
			t.Fatal(tc.file, err)
		}
		if !reflect.DeepEqual(g.Risks, tc.want) {
			t.Errorf("%s:\ngot  %v\nwant %v", tc.file, g.Risks, tc.want)
		}
		pkgs := map[string]bool{}
		for _, id := range g.Packages() {
			pkgs[id] = true
		}
		for id := range tc.want {
			if !pkgs[id] {
				t.Errorf("%s: %s has risks but is not a package of the graph", tc.file, id)
			}
		}
	}
}

func TestSourceRisk(t *testing.T) {
	for ref, want := range map[string]string{
		"":          "",
		"1.0.0":     "",
		"npm:1.0.0": "",
		"https://registry.npmjs.org/a/-/a-1.0.0.tgz":   "",
		"https://registry.yarnpkg.com/a/-/a-1.0.0.tgz": "",
		"https://tok:x@npm.corp.example/a.tgz":         "registry:npm.corp.example",
		"http://u:p@h.example/a.tgz?t=1":               "http:http://h.example/a.tgz",
		"git+https://u:tok@github.com/a/b.git#abc":     "git:git+https://github.com/a/b.git",
		"git+ssh://git@github.com:a/b.git#abc":         "git:github.com:a/b.git",
		"git@github.com:a/b.git":                       "git:github.com:a/b.git",
		"github:a/b#abc":                               "git:github:a/b",
		"link:../x":                                    "file:../x",
	} {
		if got := SourceRisk(ref); got != want {
			t.Errorf("%q: got %q, want %q", ref, got, want)
		}
	}
}
