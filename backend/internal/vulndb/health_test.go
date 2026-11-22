package vulndb

import (
	"context"
	"net/http"
	"os"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHealthParsers(t *testing.T) {
	if n, err := parseMaintainers(fixture(t, "npm-version.json")); err != nil || n != 3 {
		t.Errorf("maintainers %d %v", n, err)
	}
	if repo, link := parseSourceRepo(fixture(t, "depsdev-version.json")); repo != "github.com/expressjs/express" || link != "git+https://github.com/expressjs/express.git" {
		t.Errorf("repo %q link %q", repo, link)
	}
	if s, err := parseScorecard(fixture(t, "depsdev-project.json")); err != nil || s == nil || *s != 8.5 {
		t.Errorf("scorecard %v %v", s, err)
	}
	if s, err := parseScorecard([]byte(`{"projectKey":{"id":"gitlab.com/a/b"}}`)); err != nil || s != nil {
		t.Errorf("unscored %v %v", s, err)
	}
}

func TestPackageHealth(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/npm/@types%2fnode/22.1.0":
			w.Write(fixture(t, "npm-version.json"))
		case "/depsdev/v3/systems/npm/packages/%40types%2Fnode/versions/22.1.0":
			w.Write(fixture(t, "depsdev-version.json"))
		case "/depsdev/v3/projects/github.com%2Fexpressjs%2Fexpress":
			w.Write(fixture(t, "depsdev-project.json"))
		default:
			http.Error(w, "unexpected "+r.URL.EscapedPath(), 400)
		}
	}))
	h := c.PackageHealths(context.Background(), map[string]string{"@types/node": "22.1.0"})["@types/node"]
	if h.Maintainers == nil || *h.Maintainers != 3 || h.Scorecard == nil || *h.Scorecard != 8.5 || h.Repository != "https://github.com/expressjs/express" {
		t.Errorf("health %+v", h)
	}
}

func TestRepoURL(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/expressjs/express":                   "https://github.com/expressjs/express",
		"git+https://github.com/expressjs/express.git":   "https://github.com/expressjs/express",
		"git://github.com/o/r.git":                       "https://github.com/o/r",
		"git+ssh://git@github.com/o/r.git":               "https://github.com/o/r",
		"git@gitlab.com:group/sub/r.git":                 "https://gitlab.com/group/sub/r",
		"github:o/r":                                     "https://github.com/o/r",
		"gitlab:o/r":                                     "https://gitlab.com/o/r",
		"http://GitHub.com/o/r/":                         "https://github.com/o/r",
		"https://github.com/o/r#readme":                  "https://github.com/o/r",
		"https://git.example.org/o/r/tree/main/packages": "https://git.example.org/o/r/tree/main/packages",
		"":                                    "",
		"o/r":                                 "",
		"javascript:alert(1)//github.com/o/r": "",
		"file:///etc/passwd":                  "",
		"https://evil@github.com/o/r":         "",
		"https://github.com:8443/o/r":         "",
		"https://127.0.0.1/o/r":               "",
		"https://localhost/o/r":               "",
		"https://github.com/o":                "",
		"svn+https://svn.example.org/o/r":     "",
		"https://exa mple.org/o/r":            "",
	} {
		if got := RepoURL(in); got != want {
			t.Errorf("RepoURL(%q) = %q, want %q", in, got, want)
		}
	}
}
