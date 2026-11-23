package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrip(t *testing.T) {
	cases := []struct{ in, want string }{
		{`a = "x//y" // c`, `a = "    "     `},
		{"a = 'it\\'s' /* c\nd */ b", "a = '     '     \n     b"},
		{"x = `hi ${name + `in${y}`} there`", "x = `   ${name + `  ${y}`}      `"},
		{`r = /a\/"b[/]/g; d = a / b / c`, `r = /        /g; d = a / b / c`},
		{`return /https?:/.test(u)`, `return /       /.test(u)`},
		{`if (a) { s = "}" }`, `if (a) { s = " " }`},
	}
	for _, c := range cases {
		if got := string(Strip([]byte(c.in), "JavaScript")); got != c.want {
			t.Errorf("Strip(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	svelte := "<script>\nlet a = 'k' // c\n</script>\n<p>{a}</p>\n"
	got := string(Strip([]byte(svelte), "Svelte"))
	if !strings.Contains(got, "let a = ' '") || strings.Contains(got, "<p>") || len(got) != len(svelte) {
		t.Errorf("Strip svelte: %q", got)
	}
}

func TestCount(t *testing.T) {
	f := File{Lang: "TypeScript", Src: []byte("// header\n\nconst a = 1 // trailing\n/*\n block\n*/\nconst b = `\n// not a comment\n`\n")}
	f.Code = Strip(f.Src, f.Lang)
	langs, total := Count([]File{f, {Lang: "JSON", Src: []byte("{}")}})
	if len(langs) != 1 {
		t.Fatalf("langs = %+v", langs)
	}
	l := langs[0]
	if l.Code != 4 || l.Comments != 4 || l.Blanks != 1 || total != 4 || l.Files != 1 {
		t.Errorf("got %+v total %d, want code 4 comments 4 blanks 1", l, total)
	}
}

func TestWalk(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitignore", "secret.json\ngen/\n")
	write("src/a.ts", "export const a = 1\n")
	write("src/.env", "X=1\n") // hidden file in a normal dir: read
	write("src/gen/b.ts", "x") // ignored dir
	write("secret.json", "{}") // ignored file
	write("node_modules/x/index.js", "x")
	write(".hidden/c.js", "x")
	write(".github/workflows/ci.yml", "on: push\n")
	write("logo.png", "\x89PNG\x00")
	write("bin.js", "a\x00b")
	write("pkg/.gitignore", "*.js\n")
	write("pkg/x.js", "x")
	write("pkg/y.ts", "y")
	files, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range files {
		got = append(got, f.Path)
	}
	// .gitignore files have no language, so they are not returned.
	want := ".github/workflows/ci.yml,pkg/y.ts,src/.env,src/a.ts"
	if strings.Join(got, ",") != want {
		t.Errorf("Walk = %v, want %s", got, want)
	}
	if !files[3].IsCode() || files[2].IsCode() {
		t.Errorf("IsCode wrong: %+v", files)
	}
}

func TestIsTest(t *testing.T) {
	for p, want := range map[string]bool{
		"src/a.test.ts": true, "src/a.spec.tsx": true, "test/helpers.ts": true, "src/__tests__/a.ts": true,
		"src/a.ts": false, "src/testing.ts": false, "src/latest/a.ts": false,
	} {
		if IsTest(p) != want {
			t.Errorf("IsTest(%q) = %v", p, !want)
		}
	}
}
