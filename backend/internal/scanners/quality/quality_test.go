package quality

import (
	"fmt"
	"strings"
	"testing"

	"limier/internal/scanners/source"
)

func mkFile(p, lang, src string) source.File {
	return source.File{Path: p, Lang: lang, Src: []byte(src), Code: source.Strip([]byte(src), lang)}
}

func funcs(t *testing.T, lang, src string) []Function {
	t.Helper()
	fns, _ := analyzeFile(mkFile("a.ts", lang, src))
	return fns
}

func TestFunctionDetection(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string // name/params/complexity
	}{
		{"declaration", "function foo(a, b) { return a }", []string{"foo/2/1"}},
		{"async generator", "async function* gen() { yield 1 }", []string{"gen/0/1"}},
		{"arrow const", "const f = (a, { b, c }) => { return a }", []string{"f/2/1"}},
		{"arrow single param", "items.forEach(x => { if (x) go() })", []string{"(anonyme)/1/2"}},
		{"async arrow", "export const run = async (a) => { await a }", []string{"run/1/1"}},
		{"property arrow", "const o = { onClick: (e) => { e.stop() } }", []string{"onClick/1/1"}},
		{"function expression", "const h = function (a) { return a }", []string{"h/1/1"}},
		{"class", "class A extends B {\n constructor(a) { super(a) }\n get x() { return 1 }\n static async load(id) { if (id) {} }\n}", []string{"constructor/1/1", "x/0/1", "load/1/2"}},
		{"object methods", "export default { data() { return {} }, mounted() { this.go() } }", []string{"data/0/1", "mounted/0/1"}},
		{"nested", "function outer(a) {\n if (a) {}\n const inner = () => { if (a && b) {} }\n return a || b\n}", []string{"outer/1/3", "inner/0/3"}},
		{"ts generics and return type", "function foo<T>(a: T, b?: Map<string, T>): T { return a }", []string{"foo/2/1"}},
		{"ts method return object type", "class S { get(id: string): { a?: number } { return {} } }", []string{"get/1/1"}},
		{"ts arrow return type", "const f = async (a: number): Promise<void> => { return }", []string{"f/1/1"}},
		{"ts optional and function types do not count", "function f(cb?: (x: number) => void) { const o: { a?: string, b: () => void } = {}; let c = o?.a ?? 'x'; type X = (a?: number) => void }", []string{"f/1/2"}},
		{"trailing comma", "function f(\n a,\n b,\n) {}", []string{"f/2/1"}},
		{"control blocks are not functions", "if (a) { } else { } for (;;) { } while (x) { } switch (y) { case 1: { } } try { } catch (e) { } finally { }", nil},
		{"class and interface bodies", "interface I { a(): { b: number } }\nclass C<T> implements I { }", nil},
	}
	for _, c := range cases {
		var got []string
		for _, f := range funcs(t, "TypeScript", c.src) {
			got = append(got, fmt.Sprintf("%s/%d/%d", f.Name, f.Params, f.Complexity))
		}
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestComplexity(t *testing.T) {
	cases := []struct {
		src  string
		want int
	}{
		{"function f() { return 1 }", 1},
		// if, else if, for, while, case×2, catch, &&, ||, ??, ternary
		{`function f(a) {
  if (a) {} else if (b) {} else {}
  for (const x of a) {}
  do { a-- } while (a > 0)
  switch (a) { case 1: break; case 2: break; default: }
  try {} catch {}
  return (a && b) || (c ?? d) ? 1 : 2
}`, 12},
		{"function f(a) { return a?.b?.c ?? a?.[0] }", 2},
		{"function f(a) { p.catch(e => e); return a.if }", 1},
	}
	for _, c := range cases {
		fns := funcs(t, "TypeScript", c.src)
		if len(fns) == 0 || fns[0].Complexity != c.want {
			t.Errorf("%q: got %+v, want complexity %d", c.src, fns, c.want)
		}
	}
}

func rules(r Report) []string {
	var out []string
	for _, i := range r.Issues {
		out = append(out, fmt.Sprintf("%s:%s:%d:%s", i.Rule, i.Severity, i.Line, i.Detail))
	}
	return out
}

func TestRules(t *testing.T) {
	deep := "function f(a) {\n if (a) {\n  if (a) {\n   if (a) {\n    if (a) {\n     if (a) { go() }\n    }\n   }\n  }\n }\n}"
	cases := []struct {
		name, path, lang, src string
		want                  []string
	}{
		{"complex medium", "a.js", "JavaScript", "function f(a) {" + strings.Repeat(" if (a) {}", 16) + " }", []string{"quality.complex-function:medium:1:complexité 17"}},
		{"complex high", "a.js", "JavaScript", "function f(a) {" + strings.Repeat(" a && b;", 31) + " }", []string{"quality.complex-function:high:1:complexité 32"}},
		{"long function low", "a.js", "JavaScript", "function f() {\n" + strings.Repeat("go()\n", 85) + "}", []string{"quality.long-function:low:1:87 lignes"}},
		{"long function medium", "a.js", "JavaScript", "function f() {\n" + strings.Repeat("go()\n", 160) + "}", []string{"quality.long-function:medium:1:162 lignes"}},
		{"long file", "a.js", "JavaScript", strings.Repeat("go()\n// c\n\n", 501), []string{"quality.long-file:low:1:501 lignes"}},
		{"deep nesting", "a.js", "JavaScript", deep, []string{"quality.deep-nesting:low:6:profondeur 5"}},
		{"object literals do not nest", "a.js", "JavaScript", "function f() { return { a: { b: { c: { d: { e: 1 } } } } } }", nil},
		{"too many params", "a.js", "JavaScript", "function f(a, b, c, d, e, g) {}", []string{"quality.too-many-params:low:1:6 paramètres"}},
		{"nested ternary", "a.js", "JavaScript", "const a = x ? 1 : y ? 2 : 3\nconst b = (x ? 1 : 2) + (y ? 3 : 4)\nconst c = x ? (y ? 1 : 2) : 3", []string{"quality.nested-ternary:low:1:", "quality.nested-ternary:low:3:"}},
		{"ternaries across ASI lines", "a.js", "JavaScript", "a = x ? 1 : 2\nb = y ? 3 : 4\nc = z\n  ? 5\n  : 6", nil},
		{"empty catch", "a.js", "JavaScript", "try { a() } catch (e) {}\ntry { a() } catch { /* nothing */ }\np.catch(() => {})\np.catch(function (e) { })\ntry {} catch (e) { log(e) }\np.catch(e => log(e))",
			[]string{"quality.empty-catch:medium:1:", "quality.empty-catch:medium:2:", "quality.empty-catch:medium:3:", "quality.empty-catch:medium:4:"}},
		{"console grouped", "src/a.js", "JavaScript", "a()\nconsole.log(1)\nconsole.debug(2)\nconsole.error(3)\n// console.log(4)\ns = 'console.log(5)'", []string{"quality.console-log:info:2:2"}},
		{"console in test", "src/a.test.js", "JavaScript", "console.log(1)", nil},
		{"console in script", "scripts/x.js", "JavaScript", "console.log(1)", nil},
		{"console in config", "vite.config.js", "JavaScript", "console.log(1)", nil},
		{"debugger", "a.js", "JavaScript", "function f() {\n  debugger\n}\n// debugger", []string{"quality.debugger:medium:2:"}},
		{"todo", "a.js", "JavaScript", "// TODO: fix   this\nconst s = '// TODO not a comment'\n/*\n * FIXME later\n */\nconst url = 'http://x' // HACK\nconst todo = 1 // todo lowercase is prose",
			[]string{"quality.todo:info:1:TODO: fix this", "quality.todo:info:4:FIXME later", "quality.todo:info:6:HACK"}},
		{"todo inside template expression", "a.js", "JavaScript", "const s = `a ${b /* XXX */} c // TODO no`", []string{"quality.todo:info:1:XXX"}},
		{"ts any", "a.ts", "TypeScript", "let a: any\nconst b = c as any\nconst d = <any>e\nconst many = 1", []string{"quality.ts-any:info:1:3"}},
		{"any at end of file", "a.ts", "TypeScript", "let a: Array<any", nil},
		{"any in js ignored", "a.js", "JavaScript", "const b = c ? d : any", nil},
		{"ts ignore", "a.ts", "TypeScript", "// @ts-ignore\na()\n/* eslint-disable */\n// eslint-disable-next-line no-console\n// @ts-nocheck", []string{"quality.ts-ignore:low:1:@ts-ignore", "quality.ts-ignore:low:3:eslint-disable", "quality.ts-ignore:low:5:@ts-nocheck"}},
	}
	for _, c := range cases {
		got := rules(Analyze([]source.File{mkFile(c.path, c.lang, c.src)}))
		if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestFixture(t *testing.T) {
	files, err := source.Walk("testdata/project")
	if err != nil {
		t.Fatal(err)
	}
	r := Analyze(files)
	want := []string{
		"quality.debugger:medium:6:",
		"quality.empty-catch:medium:7:",
		"quality.empty-catch:medium:14:",
		"quality.nested-ternary:low:4:",
		"quality.ts-any:info:2:1",
		"quality.todo:info:3:FIXME: handle missing title",
		"quality.todo:info:1:TODO: retry on 503",
		"quality.console-log:info:5:1",
		"quality.ts-any:info:8:1",
	}
	if got := rules(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("fixture:\n got %q\nwant %q", got, want)
	}
	if r.Functions != 4 || // load, save, onClick, the .catch arrow
		len(r.Hotspots) != 0 {
		t.Errorf("functions %d hotspots %v", r.Functions, r.Hotspots)
	}
	for _, i := range r.Issues {
		if !strings.HasPrefix(i.File, "src/") {
			t.Errorf("issue outside src: %+v", i)
		}
	}
}

func TestHotspots(t *testing.T) {
	var files []source.File
	for i := range 25 {
		files = append(files, mkFile(fmt.Sprintf("f%02d.js", i), "JavaScript", "function f(a) {"+strings.Repeat(" a && b;", 10+i)+" }"))
	}
	r := Analyze(files)
	if len(r.Hotspots) != 20 || r.Hotspots[0].Complexity != 35 || r.Hotspots[19].Complexity != 16 || r.Functions != 25 {
		t.Errorf("hotspots %+v", r.Hotspots)
	}
}

func TestAddChurn(t *testing.T) {
	fn := func(n int) string { return "function f(a) {" + strings.Repeat(" a && b;", n) + " }\n" }
	r := Analyze([]source.File{
		mkFile("complex.js", "JavaScript", fn(30)),      // complexity 31, never touched
		mkFile("busy.js", "JavaScript", fn(12)+fn(2)),   // max 13, touched 5 times
		mkFile("simple.js", "JavaScript", fn(1)+"\n\n"), // complexity 2, touched 9 times
	})
	if r.Hotspots[0].File != "complex.js" || len(r.HotFiles) != 0 {
		t.Fatalf("without churn: %+v %+v", r.Hotspots, r.HotFiles)
	}
	r.AddChurn(map[string]int{"busy.js": 5, "simple.js": 9, "gone.js": 50})
	if h := r.Hotspots; len(h) != 2 || h[0].File != "busy.js" || h[0].Churn != 5 || h[0].Score != 65 || h[1].Score != 0 {
		t.Errorf("hotspots %+v", h)
	}
	want := []FileHotspot{{File: "busy.js", Churn: 5, Complexity: 13, Lines: 3, Score: 65}, {File: "simple.js", Churn: 9, Complexity: 2, Lines: 4, Score: 18}}
	if fmt.Sprint(r.HotFiles) != fmt.Sprint(want) {
		t.Errorf("hot files\n got %+v\nwant %+v", r.HotFiles, want)
	}
}

func BenchmarkAnalyze(b *testing.B) {
	src := strings.Repeat("export function f(a, b) {\n  if (a && b) { return a ? b : c?.d ?? 1 }\n  for (const x of a) { console.log(x) } // TODO\n  return () => { try { go() } catch {} }\n}\n", 20000)
	f := mkFile("big.ts", "TypeScript", src)
	b.ResetTimer()
	for range b.N {
		Analyze([]source.File{f})
	}
}
