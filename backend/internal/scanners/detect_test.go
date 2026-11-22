package scanners

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

func fakeRepo(files map[string]string) ([]string, func(string) ([]byte, error)) {
	tree := make([]string, 0, len(files))
	for p := range files {
		tree = append(tree, p)
	}
	return tree, func(p string) ([]byte, error) {
		c, ok := files[p]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(c), nil
	}
}

func TestDetectFromFiles(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  Detection
	}{
		{
			name:  "missing package.json",
			files: map[string]string{"README.md": "", "go.mod": ""},
			want:  Detection{IgnoreReason: ReasonNoPackageJSON},
		},
		{
			name:  "invalid package.json",
			files: map[string]string{"package.json": "{"},
			want:  Detection{IgnoreReason: ReasonInvalidPackageJSON + ": unexpected end of JSON input"},
		},
		{
			name:  "npm with package-lock",
			files: map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": "{}"},
			want:  Detection{NodeProject: true, PackageManager: "npm", Lockfile: "package-lock.json"},
		},
		{
			name:  "npm shrinkwrap",
			files: map[string]string{"package.json": `{}`, "npm-shrinkwrap.json": "{}"},
			want:  Detection{NodeProject: true, PackageManager: "npm", Lockfile: "npm-shrinkwrap.json"},
		},
		{
			name:  "pnpm wins over others",
			files: map[string]string{"package.json": `{}`, "pnpm-lock.yaml": "", "yarn.lock": "", "package-lock.json": ""},
			want:  Detection{NodeProject: true, PackageManager: "pnpm", Lockfile: "pnpm-lock.yaml"},
		},
		{
			name:  "yarn over npm",
			files: map[string]string{"package.json": `{}`, "yarn.lock": "", "package-lock.json": ""},
			want:  Detection{NodeProject: true, PackageManager: "yarn", Lockfile: "yarn.lock"},
		},
		{
			name:  "packageManager field fallback",
			files: map[string]string{"package.json": `{"packageManager":"yarn@4.1.0"}`},
			want:  Detection{NodeProject: true, PackageManager: "yarn"},
		},
		{
			name:  "default npm",
			files: map[string]string{"package.json": `{}`},
			want:  Detection{NodeProject: true, PackageManager: "npm"},
		},
		{
			name: "npm monorepo with 5 workspaces, negation and dockerfiles",
			files: map[string]string{
				"package.json":                           `{"name":"root","workspaces":["packages/*","apps/**","tools/cli","!packages/legacy"]}`,
				"package-lock.json":                      "{}",
				"packages/a/package.json":                `{"name":"@x/a"}`,
				"packages/b/package.json":                `{"name":"@x/b"}`,
				"packages/legacy/package.json":           `{"name":"legacy"}`,
				"packages/b/node_modules/z/package.json": `{"name":"z"}`,
				"apps/web/package.json":                  `{"name":"web"}`,
				"apps/group/api/package.json":            `{"name":"api"}`,
				"tools/cli/package.json":                 `{}`,
				"tools/other/package.json":               `{"name":"other"}`,
				"apps/web/src/index.ts":                  "",
			},
			want: Detection{
				NodeProject: true, PackageManager: "npm", Lockfile: "package-lock.json",
				Workspaces: []Workspace{
					{Dir: "apps/group/api", Name: "api"},
					{Dir: "apps/web", Name: "web"},
					{Dir: "packages/a", Name: "@x/a"},
					{Dir: "packages/b", Name: "@x/b"},
					{Dir: "tools/cli", Name: ""},
				},
			},
		},
		{
			name: "yarn classic workspaces object",
			files: map[string]string{
				"package.json":          `{"private":true,"workspaces":{"packages":["libs/*"],"nohoist":["**"]}}`,
				"yarn.lock":             "",
				"libs/one/package.json": `{"name":"one"}`,
				"libs/two/package.json": `{"name":"two"}`,
				"libs/three/README.md":  "",
			},
			want: Detection{
				NodeProject: true, PackageManager: "yarn", Lockfile: "yarn.lock",
				Workspaces: []Workspace{{Dir: "libs/one", Name: "one"}, {Dir: "libs/two", Name: "two"}},
			},
		},
		{
			name: "pnpm workspace yaml",
			files: map[string]string{
				"package.json":               `{}`,
				"pnpm-lock.yaml":             "",
				"pnpm-workspace.yaml":        "packages:\n  - 'packages/*'\n  - '!**/test/**'\n",
				"packages/a/package.json":    `{"name":"a"}`,
				"packages/test/package.json": `{"name":"t"}`,
			},
			want: Detection{
				NodeProject: true, PackageManager: "pnpm", Lockfile: "pnpm-lock.yaml",
				Workspaces: []Workspace{{Dir: "packages/a", Name: "a"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, read := fakeRepo(tt.files)
			got, err := DetectFromFiles(tree, read)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestDetectFromFilesReadError(t *testing.T) {
	boom := errors.New("boom")
	_, err := DetectFromFiles([]string{"package.json"}, func(string) ([]byte, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestMatchSegments(t *testing.T) {
	tests := []struct {
		pat, dir string
		want     bool
	}{
		{"packages/*", "packages/a", true},
		{"packages/*", "packages/a/b", false},
		{"packages/**", "packages/a/b", true},
		{"**", "x/y", true},
		{"tools/cli", "tools/cli", true},
		{"tools/cli", "tools/clix", false},
		{"apps/*-svc", "apps/user-svc", true},
	}
	for _, tt := range tests {
		got := matchAny([][]string{splitPat(tt.pat)}, splitPat(tt.dir))
		if got != tt.want {
			t.Errorf("match(%q,%q)=%v want %v", tt.pat, tt.dir, got, tt.want)
		}
	}
}

func splitPat(s string) []string { return strings.Split(s, "/") }
