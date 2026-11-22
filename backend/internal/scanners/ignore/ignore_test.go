package ignore_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"limier/internal/scanners/ignore"
	"limier/internal/scanners/quality"
	"limier/internal/scanners/sast"
	"limier/internal/scanners/secrets"
	"limier/internal/scanners/source"
)

func TestParse(t *testing.T) {
	d := func(line int, reason string, rules ...string) ignore.Directive {
		return ignore.Directive{Rules: rules, Reason: reason, Line: line}
	}
	for _, c := range []struct {
		name, src string
		want      []ignore.Directive
	}{
		{"trailing //", "eval(x) // limier-ignore sast.eval", []ignore.Directive{d(1, "", "sast.eval")}},
		{"block comment", "eval(x) /* limier-ignore sast.eval -- constant */", []ignore.Directive{d(1, "constant", "sast.eval")}},
		{"hash", "KEY=v # limier-ignore secret.generic -- dev only", []ignore.Directive{d(1, "dev only", "secret.generic")}},
		{"html", "<div>{@html x}</div> <!-- limier-ignore sast.xss -- sanitized -->", []ignore.Directive{d(1, "sanitized", "sast.xss")}},
		{"multiple rules", "x // limier-ignore sast.eval, quality.debugger,sast.xss", []ignore.Directive{d(1, "", "sast.eval", "quality.debugger", "sast.xss")}},
		{"next non-empty line", "// limier-ignore sast.eval -- why\n\n  eval(x)", []ignore.Directive{d(3, "why", "sast.eval")}},
		{"stacked directives", "// limier-ignore sast.eval\n// limier-ignore sast.xss\neval(x)", []ignore.Directive{d(3, "", "sast.eval"), d(3, "", "sast.xss")}},
		{"file level", "// header\n/* limier-ignore-file quality.console-log -- CLI */\ncode", []ignore.Directive{d(0, "CLI", "quality.console-log")}},
		{"file level too late", "\n\n\n\n\n\n\n\n\n\n// limier-ignore-file quality.console-log", nil},
		{"bare is rejected", "eval(x) // limier-ignore", nil},
		{"bare with reason is rejected", "eval(x) // limier-ignore -- trust me", nil},
		{"words are not rules", "eval(x) // limier-ignore everything here", nil},
		{"not in a comment", "const s = 'limier-ignore sast.eval'", nil},
		{"glued word", "x // limier-ignored sast.eval", nil},
		{"crlf", "// limier-ignore sast.eval\r\neval(x)\r\n", []ignore.Directive{d(2, "", "sast.eval")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := ignore.Parse([]byte(c.src)); !reflect.DeepEqual(got, c.want) {
				t.Errorf("Parse(%q) = %+v, want %+v", c.src, got, c.want)
			}
		})
	}
}

func TestFilterSecretNeedsReason(t *testing.T) {
	files := []source.File{{Path: ".env", Src: []byte("A=1 # limier-ignore secret.generic\nB=2 # limier-ignore secret.generic -- dev\n")}}
	list := []source.Issue{{Rule: "secret.generic", File: ".env", Line: 1}, {Rule: "secret.generic", File: ".env", Line: 2}}
	ig := ignore.Filter(files, &list)
	if len(list) != 1 || list[0].Line != 1 || len(ig) != 1 || ig[0].Line != 2 || ig[0].Reason != "dev" {
		t.Errorf("kept %+v, ignored %+v", list, ig)
	}
}

// TestFilterProject runs the real analysers on the fixture and filters their findings.
func TestFilterProject(t *testing.T) {
	// The .env file is stored as dot.env: the repo's .gitignore would drop the real name.
	dir := t.TempDir()
	src := filepath.Join("testdata", "project")
	for _, n := range []string{"src/app.js", "src/cli.js", "dot.env"} {
		b, err := os.ReadFile(filepath.Join(src, n))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, filepath.FromSlash(n))
		if n == "dot.env" {
			dst = filepath.Join(dir, ".env")
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := source.Walk(dir)
	if err != nil {
		t.Fatal(err)
	}
	sec, flaws, smells := secrets.Analyze(files), sast.Analyze(files), quality.Analyze(files).Issues
	ig := ignore.Filter(files, &sec, &flaws, &smells)

	type key struct {
		rule, file string
		line       int
	}
	keys := func(l []source.Issue) (out []key) {
		for _, i := range l {
			if i.Rule == "sast.eval" || i.Rule == "secret.generic" || i.Rule == "quality.console-log" {
				out = append(out, key{i.Rule, i.File, i.Line})
			}
		}
		return out
	}
	var hidden []key
	for _, i := range ig {
		hidden = append(hidden, key{i.Rule, i.File, i.Line})
	}
	// Line 6 has no directive and line 8 follows a bare limier-ignore; the secret without a reason stays.
	wantKept := []key{{"secret.generic", ".env", 2}, {"sast.eval", "src/app.js", 6}, {"sast.eval", "src/app.js", 8}}
	wantHidden := []key{{"secret.generic", ".env", 4}, {"sast.eval", "src/app.js", 2}, {"sast.eval", "src/app.js", 5}, {"quality.console-log", "src/cli.js", 3}}
	if got := append(append(keys(sec), keys(flaws)...), keys(smells)...); !reflect.DeepEqual(got, wantKept) {
		t.Errorf("kept %v, want %v", got, wantKept)
	}
	if !reflect.DeepEqual(hidden, wantHidden) {
		t.Errorf("ignored %v, want %v", hidden, wantHidden)
	}
}
