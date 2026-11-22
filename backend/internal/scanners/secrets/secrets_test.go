package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"limier/internal/scanners/source"
)

// rnd builds a token body that matches the regexes without being a real secret (and without
// tripping push protection, since no full token appears in the source).
func rnd(n int, alphabet string) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteByte(alphabet[(i*7+3)%len(alphabet)])
	}
	return b.String()
}

const (
	b62 = "A1b2C3d4E5f6G7h8J9k0LmNpQrStUvWyZ"
	hex = "0123456789abcdef"
	up  = "Q7R2T9W4Y6U1I3O5PLMKNB"
)

func js(p, src string) source.File {
	return source.File{Path: p, Lang: "JavaScript", Src: []byte(src), Code: source.Strip([]byte(src), "JavaScript")}
}

func txt(p, lang, src string) source.File { return source.File{Path: p, Lang: lang, Src: []byte(src)} }

func find(issues []source.Issue, rule, file string) *source.Issue {
	for i := range issues {
		if issues[i].Rule == rule && issues[i].File == file {
			return &issues[i]
		}
	}
	return nil
}

func TestProviders(t *testing.T) {
	cases := []struct{ rule, sev, secret, line string }{
		{"secret.aws-access-key", "high", "AKIA" + rnd(16, up), "id = %q"},
		{"secret.aws-secret-key", "high", rnd(40, b62+"/+"), "aws_secret_access_key = %s"},
		{"secret.github-token", "high", "ghp_" + rnd(36, b62), "t = %q"},
		{"secret.github-token", "high", "github_pat_" + rnd(60, b62+"_"), "t = %q"},
		{"secret.gitlab-token", "high", "glpat-" + rnd(20, b62), "t = %q"},
		{"secret.slack-token", "high", "xoxb-" + rnd(24, b62), "t = %q"},
		{"secret.slack-webhook", "high", "https://hooks.slack.com/services/T" + rnd(8, up) + "/B" + rnd(8, up) + "/" + rnd(24, b62), "u = %q"},
		{"secret.stripe-live-key", "high", "sk_live_" + rnd(24, b62), "k = %q"},
		{"secret.stripe-test-key", "low", "sk_test_" + rnd(24, b62), "k = %q"},
		{"secret.google-api-key", "high", "AIza" + rnd(35, b62), "k = %q"},
		{"secret.openai-key", "high", "sk-" + rnd(48, b62), "k = %q"},
		{"secret.openai-key", "high", "sk-proj-" + rnd(48, b62), "k = %q"},
		{"secret.anthropic-key", "high", "sk-ant-api03-" + rnd(40, b62), "k = %q"},
		{"secret.npm-token", "high", "npm_" + rnd(36, b62), "k = %q"},
		{"secret.npm-token", "high", rnd(36, b62), "//registry.npmjs.org/:_authToken=%s"},
		{"secret.sendgrid-key", "high", "SG." + rnd(22, b62) + "." + rnd(43, b62), "k = %q"},
		{"secret.twilio-key", "high", "SK" + rnd(32, hex), "twilio(%q)"},
		{"secret.private-key", "high", "-----BEGIN RSA PRIVATE KEY-----", "%s\nMIIE\n-----END RSA PRIVATE KEY-----"},
		{"secret.jwt", "medium", "eyJ" + rnd(20, b62) + ".eyJ" + rnd(30, b62) + "." + rnd(43, b62), "j = %q"},
		{"secret.url-credentials", "high", rnd(16, b62), "db = 'postgres://admin:%s@db.internal:5432/app'"},
	}
	var files []source.File
	for i, c := range cases {
		files = append(files, txt(fmt.Sprintf("c%02d.txt", i), "Text", "first line\n"+fmt.Sprintf(c.line, c.secret)+"\n"))
	}
	issues := Analyze(files)
	for i, c := range cases {
		is := find(issues, c.rule, fmt.Sprintf("c%02d.txt", i))
		if is == nil {
			t.Errorf("%s: no issue for %s", c.rule, c.secret)
			continue
		}
		if is.Severity != c.sev || is.Line != 2 {
			t.Errorf("%s: got %+v", c.rule, *is)
		}
		if c.rule != "secret.private-key" && !strings.HasSuffix(is.Detail, fmt.Sprintf("…(%d car.)", len(c.secret))) {
			t.Errorf("%s: detail %q", c.rule, is.Detail)
		}
	}
	for _, is := range issues {
		for _, c := range cases {
			if c.rule != "secret.private-key" && strings.Contains(is.Detail, c.secret[4:]) {
				t.Errorf("secret in clear in %+v", is)
			}
		}
	}
	// an Anthropic key is not also reported as an OpenAI one
	if is := find(issues, "secret.openai-key", "c12.txt"); is != nil {
		t.Errorf("anthropic key matched openai: %+v", *is)
	}
}

func TestNoFalsePositives(t *testing.T) {
	issues := Analyze([]source.File{
		txt("a.txt", "Text", "id = AKIAXXXXXXXXXXXXXXXX\nghp_"+strings.Repeat("x", 36)+"\nhttps://user:password@example.com\npostgres://postgres:postgres@localhost\n${DB_URL}\n"),
		txt("b.yml", "YAML", "author: Nicolas Despres Lambert\npassword: ${DB_PASSWORD}\ntoken: changeme_please_now\napi_key: '<your key>'\n"),
		txt("c.txt", "Text", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
		txt("app.js.map", "JSON", `{"k":"ghp_`+rnd(36, b62)+`"}`),
		txt("yarn.lock", "Text", "  integrity sha512-"+rnd(80, b62)+"\n  token \"ghp_"+rnd(36, b62)+"\"\n"),
		txt(".npmrc", "Env", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"),
	})
	if len(issues) != 0 {
		t.Errorf("unexpected issues: %+v", issues)
	}
}

func TestFixtureProject(t *testing.T) {
	// .env files are stored as dot.env*: the repo's .gitignore would drop the real names.
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("testdata/project")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"dot.env", "dot.env.example"} {
		if err := os.Rename(filepath.Join(dir, n), filepath.Join(dir, n[3:])); err != nil {
			t.Fatal(err)
		}
	}
	files, err := source.Walk(dir)
	if err != nil {
		t.Fatal(err)
	}
	issues := Analyze(files)
	got := map[string]source.Issue{}
	for _, is := range issues {
		got[fmt.Sprint(is.Rule, " ", is.File, ":", is.Line)] = is
		if strings.Contains(is.Detail, "Hj7kL9mN2pQ4rS6t") || strings.Contains(is.Detail, "Zq8mW2rT5vK9pLx4") || strings.Contains(is.Detail, "Vb3nM8kP2qR7sT1w") {
			t.Errorf("secret in clear: %+v", is)
		}
	}
	want := map[string]string{
		"secret.env-file .env:1":          "high",
		"secret.generic .env:2":           "medium",
		"secret.generic src/config.js:3":  "medium", // not line 1: the comment is ignored
		"secret.generic test/helper.js:1": "low",    // test path: one level down
	}
	for k, sev := range want {
		if is, ok := got[k]; !ok || is.Severity != sev {
			t.Errorf("%s: got %+v, want %s", k, is, sev)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d issues, want %d: %+v", len(got), len(want), issues)
	}
	if is := got["secret.env-file .env:1"]; is.Detail != "2" {
		t.Errorf("env-file detail = %q, want 2 values", is.Detail)
	}
	if issues[0].Severity != "high" {
		t.Errorf("not sorted: %+v", issues)
	}
}

func TestSpeed(t *testing.T) {
	line := `  const user = { name: "alice", token: getToken(), url: "https://api.example.org/v1" } // auth later` + "\n"
	big := js("big.js", strings.Repeat(line, 100_000))
	start := time.Now()
	Analyze([]source.File{big})
	if d := time.Since(start); d > time.Second {
		t.Errorf("100k lines in %v", d)
	}
}

func TestExampleFiles(t *testing.T) {
	val := rnd(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	issues := Analyze([]source.File{
		txt(".env.example", "Env", "JWT_SECRET=replace-with-a-long-random-string\nAPI_TOKEN="+val+"\n"),
		txt(".env", "Env", "JWT_SECRET=GENERATE_ME_WITH_openssl_rand_hex_32\n"),
	})
	if i := find(issues, "secret.generic", ".env.example"); i == nil || i.Line != 2 || i.Severity != source.Low {
		t.Errorf("example file: want only line 2 at low, got %+v", issues)
	}
	if find(issues, "secret.generic", ".env") != nil || find(issues, "secret.env-file", ".env") != nil {
		t.Errorf("placeholders must not be reported: %+v", issues)
	}
}
