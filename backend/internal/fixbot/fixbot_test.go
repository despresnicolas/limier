package fixbot

import (
	"strings"
	"testing"
)

const manifest = `{
    "name": "app",
    "version": "1.0.0",
    "dependencies": {
        "express": "^4.18.0"
    }
}
`

func TestSetDependency(t *testing.T) {
	in := `{
  "name": "app",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "4.17.20",
    "local": "file:../local"
  },
  "devDependencies": {
    "vitest": "~1.2.0",
    "express": ">=4.0.0"
  }
}
`
	got, err := SetDependency([]byte(in), "express", "4.21.2")
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "name": "app",
  "dependencies": {
    "express": "^4.21.2",
    "lodash": "4.17.20",
    "local": "file:../local"
  },
  "devDependencies": {
    "vitest": "~1.2.0",
    "express": ">=4.21.2"
  }
}
`
	if string(got) != want {
		t.Fatalf("got:\n%s", got)
	}
	if got, err := SetDependency([]byte(in), "lodash", "4.17.21"); err != nil || !strings.Contains(string(got), `"lodash": "4.17.21"`) {
		t.Fatalf("exact version: %v\n%s", err, got)
	}
	if _, err := SetDependency([]byte(in), "local", "2.0.0"); err == nil {
		t.Fatal("file: range must be refused")
	}
	if _, err := SetDependency([]byte(in), "qs", "6.11.0"); err == nil {
		t.Fatal("transitive package must be refused")
	}
}

func TestBumpBranchName(t *testing.T) {
	if got := BumpBranchName("limier", "packages/api", "@nestjs/core", "10.4.1"); got != "limier/bump-packages-api-nestjs-core-10.4.1" {
		t.Fatal(got)
	}
}

func TestBranchPrefix(t *testing.T) {
	for _, ok := range []string{"fix", "limier", "deps/limier", "a.b_c-d", "_x"} {
		if err := ValidBranchPrefix(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-x", ".x", "a..b", "a/", "/a", "a//b", "a b", "a~b", "a^b", "a:b", "a?b", "a*b", "a[b", "a\\b", "x.lock", "x.", strings.Repeat("a", 51)} {
		if ValidBranchPrefix(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got := BumpBranchName("--upload-pack=x", "", "lodash", "4.17.21"); got != "fix/bump-lodash-4.17.21" {
		t.Errorf("invalid prefix not replaced: %s", got)
	}
}

func TestSetOverride(t *testing.T) {
	in := "{\n    \"name\": \"app\",\n    \"overrides\": {\n        \"qs\": \"^6.5.0\",\n        \"foo\": {\"bar\": \"1.0.0\"}\n    }\n}\n"
	for _, c := range []struct {
		name, in, pm, pkg, version, want string
	}{
		{"npm adds", manifest, "npm", "qs", "6.11.0",
			"{\n    \"name\": \"app\",\n    \"version\": \"1.0.0\",\n    \"dependencies\": {\n        \"express\": \"^4.18.0\"\n    },\n    \"overrides\": {\n        \"qs\": \"6.11.0\"\n    }\n}\n"},
		{"npm raises lower, keeps operator", in, "npm", "qs", "6.11.0",
			"{\n    \"name\": \"app\",\n    \"overrides\": {\n        \"qs\": \"^6.11.0\",\n        \"foo\": {\n            \"bar\": \"1.0.0\"\n        }\n    }\n}\n"},
		{"npm keeps higher", in, "npm", "qs", "6.4.0", in},
		{"pnpm", `{"pnpm": {"overrides": {"ws@<8": ">=8"}}}`, "pnpm", "qs", "6.11.0",
			"{\n  \"pnpm\": {\n    \"overrides\": {\n      \"ws@<8\": \">=8\",\n      \"qs\": \"6.11.0\"\n    }\n  }\n}\n"},
		{"yarn", `{"name": "app"}`, "yarn", "qs", "6.11.0", "{\n  \"name\": \"app\",\n  \"resolutions\": {\n    \"qs\": \"6.11.0\"\n  }\n}\n"},
	} {
		got, err := SetOverride([]byte(c.in), c.pm, c.pkg, c.version)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		} else if string(got) != c.want {
			t.Errorf("%s:\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
	if _, err := SetOverride([]byte(in), "npm", "foo", "2.0.0"); err == nil {
		t.Error("a nested override must be refused")
	}
	if got := OverrideBranchName("deps", "@babel/core", "7.26.10"); got != "deps/override-babel-core-7.26.10" {
		t.Errorf("branch %s", got)
	}
}
