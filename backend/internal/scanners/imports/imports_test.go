package imports

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"limier/internal/scanners/source"
)

func analyze(t *testing.T, dir string) Report {
	t.Helper()
	files, err := source.Walk("testdata/" + dir)
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(files)
}

func eq[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n got %v\nwant %v", what, got, want)
	}
}

func edge(r Report, from, to string) *Edge {
	for i := range r.Edges {
		if r.Edges[i].From == from && r.Edges[i].To == to {
			return &r.Edges[i]
		}
	}
	return nil
}

func TestTSProject(t *testing.T) {
	r := analyze(t, "ts")
	eq(t, "cycles", r.Cycles, [][]string{{"src/cycle/a.ts", "src/cycle/b.ts", "src/cycle/c.ts"}})
	eq(t, "dead", r.DeadFiles, []string{"src/gone.ts"}) // only imported in a comment and a string
	eq(t, "unused deps", r.UnusedDeps, []string{"left-pad"})
	eq(t, "packages", r.ImportedPackages, map[string]bool{"lodash": true})
	eq(t, "usage", r.PackageUsage, map[string]int{"lodash": 1})
	eq(t, "unresolved", r.Unresolved, 1)
	if len(r.UnusedExports) != 1 || r.UnusedExports[0].File != "src/cycle/c.ts" || r.UnusedExports[0].Detail != "unusedHelper" || r.UnusedExports[0].Line != 3 {
		t.Errorf("unused exports: %+v", r.UnusedExports)
	}
	if e := edge(r, "src/index.ts", "src/cycle/a.ts"); e == nil || e.TypeOnly || e.Circular {
		t.Errorf("alias edge: %+v", e)
	}
	if e := edge(r, "src/cycle/a.ts", "src/cycle/b.ts"); e == nil || !e.Circular {
		t.Errorf("cycle edge (./b.js → b.ts): %+v", e)
	}
	if e := edge(r, "src/types/t2.ts", "src/types/t1.ts"); e == nil || !e.TypeOnly || e.Circular {
		t.Errorf("type-only edge: %+v", e)
	}
	if edge(r, "src/index.ts", "src/lazy.ts") == nil {
		t.Error("dynamic import not counted")
	}
	issues := r.Issues()
	if len(issues) != 4 || issues[0].Rule != RuleCycle || issues[0].Detail != "src/cycle/a.ts → src/cycle/b.ts → src/cycle/c.ts → src/cycle/a.ts" ||
		issues[2].Rule != RuleUnusedDep || issues[2].File != "package.json" {
		t.Errorf("issues: %+v", issues)
	}
}

func TestSvelteKit(t *testing.T) {
	r := analyze(t, "kit")
	eq(t, "dead", r.DeadFiles, []string{"src/lib/orphan.ts"})
	eq(t, "unused deps", r.UnusedDeps, []string(nil))
	eq(t, "cycles", len(r.Cycles), 0)
	eq(t, "unresolved", r.Unresolved, 0)
	for _, to := range []string{"src/lib/Card.svelte", "src/lib/format.ts"} {
		if edge(r, "src/routes/+page.svelte", to) == nil {
			t.Errorf("missing $lib edge to %s", to)
		}
	}
	eq(t, "unused exports", len(r.UnusedExports), 0)
}

func TestMonorepo(t *testing.T) {
	r := analyze(t, "mono")
	eq(t, "unused deps", r.UnusedDeps, []string{"packages/app: chalk", "packages/utils: unused-lib"})
	eq(t, "dead", r.DeadFiles, []string(nil))
	eq(t, "packages", r.ImportedPackages, map[string]bool{"chalk": true, "vitest": true})
	if edge(r, "packages/app/src/main.ts", "packages/utils/src/index.ts") == nil {
		t.Error("workspace import by name not linked")
	}
	eq(t, "unused exports", len(r.UnusedExports), 0)
	is := r.Issues()
	if is[0].File != "packages/app/package.json" || is[0].Detail != "chalk" {
		t.Errorf("issue: %+v", is[0])
	}
}

func TestCommentedImports(t *testing.T) {
	src := "// import a from 'x'\n/* require('y') */\nconst s = `import('z')`;\nimport b from 'w';\nexport { q as default, r }\nexport const enum E {}\n"
	f := source.File{Path: "a.ts", Lang: "TypeScript", Src: []byte(src), Code: source.Strip([]byte(src), "TypeScript")}
	got := parseImports(f)
	if len(got) != 1 || got[0].spec != "w" || got[0].line != 4 || got[0].names[0] != "default" {
		t.Errorf("imports: %+v", got)
	}
	eq(t, "exports", parseAllExports(f), []export{{"E", 6}, {"r", 5}})
}

func TestOnlyFunctionExports(t *testing.T) {
	src := `export function f() {}
export async function g() {}
export const h = (a: number): number => a
export const i = async x => x
export const j = function () {}
export const K = 1
export interface L { n: number }
export type M = string
export class N {}
function o() {}
const P = 2
export { o, P }
`
	f := source.File{Path: "a.ts", Lang: "TypeScript", Src: []byte(src), Code: source.Strip([]byte(src), "TypeScript")}
	eq(t, "function exports", parseExports(f), []export{{"f", 1}, {"g", 2}, {"h", 3}, {"i", 4}, {"j", 5}, {"o", 12}})
}

func TestJSONC(t *testing.T) {
	got := string(jsonc([]byte(`{"a": "http://x", /* c */ "b": [1,], // d
}`)))
	eq(t, "jsonc", strings.Join(strings.Fields(got), ""), `{"a":"http://x","b":[1]}`)
}

func TestSpeed(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	var files []source.File
	add := func(p, src string) {
		files = append(files, source.File{Path: p, Lang: "TypeScript", Src: []byte(src), Code: source.Strip([]byte(src), "TypeScript")})
	}
	files = append(files, source.File{Path: "package.json", Lang: "JSON", Src: []byte(`{"dependencies":{"lodash":"1"}}`)})
	body := strings.Repeat("export const v = (n: number) => n * 2; // filler\n", 45)
	for i := range 2000 { // 2000 files × 50 lines = 100k lines
		add(fmt.Sprintf("src/m%d.ts", i), fmt.Sprintf("import { v } from './m%d';\nimport _ from 'lodash';\nimport type { T } from './m%d';\n%s", (i+1)%2000, (i+7)%2000, body))
	}
	start := time.Now()
	r := Analyze(files)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("100k lines took %v", d)
	}
	if len(r.Cycles) != 1 || len(r.Cycles[0]) != 2000 {
		t.Errorf("cycles: %d", len(r.Cycles))
	}
}
