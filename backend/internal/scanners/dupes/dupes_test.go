package dupes

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"limier/internal/scanners/source"
)

func file(path, src string) source.File {
	return source.File{Path: path, Lang: "JavaScript", Src: []byte(src), Code: source.Strip([]byte(src), "JavaScript")}
}

// block is a 12-line function of ~90 tokens; names lets copies rename identifiers.
func block(fn, acc, item string) string {
	return fmt.Sprintf(`function %[1]s(list, opts) {
  let %[2]s = 0 // running total
  for (const %[3]s of list) {
    if (%[3]s.quantity <= 0) continue
    %[2]s += %[3]s.price * %[3]s.quantity
  }
  if (opts && opts.percent > 0) {
    %[2]s = %[2]s - (%[2]s * opts.percent) / 100
  }
  const label = "total: " + %[2]s
  return { value: Math.max(%[2]s, 0), label }
}
`, fn, acc, item)
}

func TestExactDuplicate(t *testing.T) {
	r := Analyze([]source.File{
		file("a.js", "const x = 1\n"+block("total", "sum", "it")),
		file("b.js", block("total", "sum", "it")+"console.log(1)\n"),
	})
	if len(r.Clones) != 1 {
		t.Fatalf("clones = %+v", r.Clones)
	}
	c := r.Clones[0]
	want := []Location{{"a.js", 2, 13}, {"b.js", 1, 12}}
	if c.Lines != 12 || fmt.Sprint(c.Locations) != fmt.Sprint(want) || c.Tokens < MinTokens {
		t.Errorf("clone = %+v", c)
	}
}

func TestRenamedDuplicate(t *testing.T) {
	r := Analyze([]source.File{
		file("a.js", block("total", "sum", "it")),
		file("b.js", block("amount", "acc", "row")),
	})
	if len(r.Clones) != 1 || len(r.Clones[0].Locations) != 2 {
		t.Fatalf("clones = %+v", r.Clones)
	}
}

func TestThreeCopiesGrouped(t *testing.T) {
	r := Analyze([]source.File{
		file("a.js", block("f", "a", "b")),
		file("b.js", "let z = 2\n"+block("g", "c", "d")),
		file("c.js", block("h", "e", "f")+"z()\n"),
	})
	if len(r.Clones) != 1 || len(r.Clones[0].Locations) != 3 {
		t.Fatalf("clones = %+v", r.Clones)
	}
	if r.DuplicatedLines != 24 {
		t.Errorf("duplicated = %d, want 24 (two copies of 12 lines)", r.DuplicatedLines)
	}
}

func TestShortDuplicateIgnored(t *testing.T) {
	// Many tokens but only 3 lines.
	src := strings.ReplaceAll(block("f", "a", "b"), "\n", " ")
	src = src[:len(src)/3] + "\n" + src[len(src)/3:2*len(src)/3] + "\n" + src[2*len(src)/3:]
	if r := Analyze([]source.File{file("a.js", src), file("b.js", src)}); len(r.Clones) != 0 {
		t.Errorf("clones = %+v", r.Clones)
	}
}

func TestImportsIgnored(t *testing.T) {
	var imports strings.Builder
	for i := range 15 {
		fmt.Fprintf(&imports, "import { a%d, b%d as c%d } from './m%d.js';\n", i, i, i, i)
	}
	imports.WriteString("import {\n  x,\n  y,\n} from 'z'\nexport * from './all'\nexport { q, w } from './qw'\n")
	imports.WriteString("const fs = require('fs')\nconst { join, resolve } = require('path')\nimport 'side-effect'\n")
	a := imports.String() + "run(1)\n"
	b := imports.String() + "go(2, 3)\n"
	if r := Analyze([]source.File{file("a.js", a), file("b.js", b)}); len(r.Clones) != 0 {
		t.Errorf("clones = %+v", r.Clones)
	}
}

func TestDataArrayIgnored(t *testing.T) {
	var data strings.Builder
	data.WriteString("export const table = [\n")
	for i := range 60 {
		fmt.Fprintf(&data, "  [%d, %d, %d, %d],\n", i, i*2, i*3, i*4)
	}
	data.WriteString("]\n")
	if r := Analyze([]source.File{file("a.js", data.String()), file("b.js", data.String())}); len(r.Clones) != 0 {
		t.Errorf("clones = %+v", r.Clones)
	}
}

func TestNearMissNeverSpansDifference(t *testing.T) {
	head := block("f", "a", "b")
	tail := block("g", "c", "d")
	a := head + "const marker = compute(1)\n" + tail
	b := head + "while (ready()) { await tick() }\n" + tail
	r := Analyze([]source.File{file("a.js", a), file("b.js", b)})
	for _, c := range r.Clones {
		for _, l := range c.Locations {
			if l.Line <= 13 && l.EndLine >= 13 {
				t.Errorf("clone spans the differing line 13: %+v", c)
			}
		}
	}
	if len(r.Clones) == 0 {
		t.Error("expected the identical halves to be reported")
	}
}

func TestRatio(t *testing.T) {
	r := Analyze([]source.File{
		file("a.js", block("f", "a", "b")),
		file("b.js", block("f", "a", "b")+"\n\n// note\nfoo()\nbar()\n"),
		{Path: "package.json", Lang: "JSON", Src: []byte("{}\n")},
	})
	if r.TotalLines != 26 || r.DuplicatedLines != 12 || math.Abs(r.Ratio-12.0/26) > 1e-9 {
		t.Errorf("total %d dup %d ratio %v", r.TotalLines, r.DuplicatedLines, r.Ratio)
	}
	if r := Analyze(nil); r.Ratio != 0 || r.Clones != nil {
		t.Errorf("empty = %+v", r)
	}
}

func TestFixtureProject(t *testing.T) {
	files, err := source.Walk("testdata/project")
	if err != nil {
		t.Fatal(err)
	}
	r := Analyze(files)
	if len(r.Clones) != 1 {
		t.Fatalf("clones = %+v", r.Clones)
	}
	want := []Location{{"src/cart.js", 4, 14}, {"src/invoice.js", 3, 13}}
	if got := r.Clones[0].Locations; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("locations = %v, want %v", got, want)
	}
}

// BenchmarkAnalyze runs on ~100k lines mixing unique code and some copy-pasted functions.
func BenchmarkAnalyze(b *testing.B) {
	stmts := []string{
		"let %s = %s.map((x) => x * %d)",
		"if (%s > %d) { %s = %s - 1 }",
		"const %s = await fetch(%s, { method: 'POST', retries: %d })",
		"for (let i = 0; i < %s.length; i++) total += %s[i] * %d",
		"try { %s.close(%s) } catch (e) { log(e, %d) }",
		"return new Map(Object.entries(%s).filter(([k]) => k !== %s && %d))",
		"%s.addEventListener('click', () => { %s.toggle(%d) })",
		"switch (%s) { case %d: %s = null; break; default: throw new Error('x') }",
	}
	var files []source.File
	lines, seed := 0, uint32(7)
	rnd := func(n int) int { seed = seed*1664525 + 1013904223; return int(seed>>8) % n }
	for f := 0; lines < 100_000; f++ {
		var sb strings.Builder
		for fn := range 10 {
			if rnd(10) == 0 {
				sb.WriteString(block(fmt.Sprintf("dup%d_%d", f, fn), "acc", "row"))
				lines += 12
				continue
			}
			fmt.Fprintf(&sb, "export function f%d_%d(a, b) {\n", f, fn)
			for range 8 + rnd(6) {
				s := stmts[rnd(len(stmts))]
				line := strings.NewReplacer("%s", fmt.Sprintf("v%d", rnd(50)), "%d", fmt.Sprint(rnd(100))).Replace(s)
				sb.WriteString("  " + line + "\n")
				lines++
			}
			sb.WriteString("}\n\n")
			lines += 2
		}
		files = append(files, file(fmt.Sprintf("src/f%d.js", f), sb.String()))
	}
	for b.Loop() {
		r := Analyze(files)
		b.ReportMetric(float64(r.TotalLines), "lines")
		b.ReportMetric(float64(len(r.Clones)), "clones")
	}
}

func TestTestFilesIgnored(t *testing.T) {
	r := Analyze([]source.File{
		file("src/a.test.js", block("total", "sum", "it")),
		file("test/b.js", block("total", "sum", "it")),
		file("src/c.js", "const x = 1\n"),
	})
	if len(r.Clones) != 0 || r.TotalLines != 1 {
		t.Errorf("tests must not count: %+v", r)
	}
}
