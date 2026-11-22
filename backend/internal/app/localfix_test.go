package app

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"limier/internal/config"
	"limier/internal/db/dbq"
)

func TestEstimateEffort(t *testing.T) {
	usage := map[string]int{"express": 12, "lodash": 2, "qs": 5}
	for _, c := range []struct {
		name, pkg, from, to string
		usage               map[string]int
		want                string
		breaking            bool
	}{
		{"compatible bump", "express", "4.17.1", "4.21.2", usage, "low", false},
		{"major, few files", "lodash", "3.10.1", "4.17.21", usage, "low", true},
		{"major, some files", "qs", "5.2.0", "6.11.0", usage, "medium", true},
		{"major, many files", "express", "4.21.2", "5.1.0", usage, "high", true},
		{"three majors", "lodash", "1.0.0", "4.0.0", usage, "high", true},
		{"0.x minor is breaking", "lodash", "0.6.2", "0.7.0", usage, "low", true},
		{"no import", "eslint", "8.0.0", "9.0.0", usage, "medium", true},
		{"no code scan", "lodash", "3.0.0", "4.0.0", nil, "medium", true},
	} {
		e := estimateEffort(c.from, c.to, false, c.usage, c.pkg)
		if e.Effort != c.want || e.Breaking != c.breaking || e.EffortReason == "" {
			t.Errorf("%s: got %+v", c.name, e)
		}
	}
}

func TestPackageUsage(t *testing.T) {
	nodes := []graphNode{
		{ID: "src/a.ts"}, {ID: "src/b.ts"},
		{ID: "node_modules/express/index.js", External: true, Package: "express"},
		{ID: "node_modules/express/lib/router.js", External: true, Package: "express"},
	}
	edges := []graphEdge{
		{From: "src/a.ts", To: "node_modules/express/index.js"},
		{From: "src/a.ts", To: "node_modules/express/lib/router.js"}, // same file counted once
		{From: "src/b.ts", To: "node_modules/express/index.js"},
		{From: "node_modules/express/index.js", To: "node_modules/express/lib/router.js"}, // not local
	}
	if got := packageUsage(nodes, edges); len(got) != 1 || got["express"] != 2 {
		t.Fatalf("usage: %v", got)
	}
}

func TestDeclaredInMonorepo(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, "repo", rel, "package.json")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("", `{"devDependencies": {"typescript": "^5.0.0"}}`)
	write("apps/api", `{"dependencies": {"express": "^4.18.0", "lodash": "^4.17.0"}}`)
	write("apps/web", `{"dependencies": {"lodash": "^4.17.0"}}`)
	a := &App{cfg: config.Config{LocalReposRoot: root}}
	got := a.declaredIn([]dbq.Project{
		{LocalPath: "repo"}, {LocalPath: "repo", Subdir: "apps/api"}, {LocalPath: "repo", Subdir: "apps/web"},
		{LocalPath: "repo", Subdir: "../outside"},
	})
	want := map[string][]string{"typescript": {""}, "express": {"apps/api"}, "lodash": {"apps/api", "apps/web"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("declaredIn = %v, want %v", got, want)
	}
}

func TestLowRisk(t *testing.T) {
	var ps []LocalFixProposal
	for _, v := range [][2]string{{"4.17.1", "4.21.2"}, {"1.2.3", "1.2.4"}, {"4.0.0", "5.0.0"}, {"0.6.2", "0.7.0"}, {"0.6.2", "0.6.3"}, {"2024-01", "2024-02"}} {
		ps = append(ps, LocalFixProposal{PackageName: v[0] + "->" + v[1], FixEffort: estimateEffort(v[0], v[1], false, nil, "")})
	}
	var got []string
	for _, p := range lowRisk(ps) {
		got = append(got, p.PackageName)
	}
	want := []string{"4.17.1->4.21.2", "1.2.3->1.2.4", "0.6.2->0.6.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lowRisk = %v, want %v", got, want)
	}
}

func TestCommitFixes(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.20\"\n  }\n}\n")
	write("apps/web/package.json", "{\n  \"dependencies\": {\n    \"lodash\": \"~4.17.20\",\n    \"express\": \"4.18.0\"\n  }\n}\n")
	write("apps/web/index.js", "require('lodash')\n")
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.AddGlob("."); err != nil {
		t.Fatal(err)
	}
	sig := &object.Signature{Name: "t", Email: "t@t", When: time.Now()}
	if _, err := wt.Commit("init", &git.CommitOptions{Author: sig}); err != nil {
		t.Fatal(err)
	}
	head, _ := repo.Head()
	if err := repo.Storer.SetReference(plumbing.NewHashReference("refs/heads/fix/existing", head.Hash())); err != nil {
		t.Fatal(err)
	}
	// An uncommitted change: the fix ignores it and leaves it alone.
	dirty := "{\"dependencies\": {\"lodash\": \"^4.0.0\"}}\n"
	write("package.json", dirty)
	before, err := wt.Status()
	if err != nil {
		t.Fatal(err)
	}

	fixes := []dbq.LocalFix{
		{PackageName: "lodash", FromVersion: "4.17.20", ToVersion: "4.17.21"},
		{ManifestDir: "apps/web", PackageName: "lodash", FromVersion: "4.17.20", ToVersion: "4.17.21"},
		{ManifestDir: "apps/web", PackageName: "express", FromVersion: "4.18.0", ToVersion: "4.21.2"},
	}
	base, commit, err := commitFixes(dir, "fix/bump-minor-patch", "pnpm", localFixMessage(fixes, "pnpm"), fixes)
	if err != nil {
		t.Fatal(err)
	}
	if base != head.Hash().String() {
		t.Fatalf("base %s, want HEAD %s", base, head.Hash())
	}
	ref, err := repo.Reference("refs/heads/fix/bump-minor-patch", false)
	if err != nil || ref.Hash().String() != commit {
		t.Fatalf("branch: %v %v", ref, err)
	}
	c, _ := repo.CommitObject(ref.Hash())
	if len(c.ParentHashes) != 1 || c.ParentHashes[0] != head.Hash() || !strings.Contains(c.Message, "`pnpm install`") {
		t.Fatalf("commit: %v %q", c.ParentHashes, c.Message)
	}
	for name, want := range map[string]string{
		"package.json":          "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.21\"\n  }\n}\n",
		"apps/web/package.json": "{\n  \"dependencies\": {\n    \"lodash\": \"~4.17.21\",\n    \"express\": \"4.21.2\"\n  }\n}\n",
		"apps/web/index.js":     "require('lodash')\n",
	} {
		f, err := c.File(name)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := f.Contents(); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	if h, _ := repo.Head(); h.Name() != head.Name() || h.Hash() != head.Hash() {
		t.Fatalf("HEAD moved: %v", h)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "package.json")); string(b) != dirty {
		t.Fatalf("working tree changed: %q", b)
	}
	if after, _ := wt.Status(); after.String() != before.String() {
		t.Fatalf("status changed:\n%s\nwas\n%s", after, before)
	}

	// An existing branch is never overwritten.
	if _, _, err := commitFixes(dir, "fix/existing", "pnpm", "m", fixes); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing branch: %v", err)
	}
	if ref, _ := repo.Reference("refs/heads/fix/existing", false); ref.Hash() != head.Hash() {
		t.Fatal("existing branch overwritten")
	}
}

func TestReleaseAge(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	ago := func(days int) time.Time { return now.Add(-time.Duration(days) * 24 * time.Hour) }
	released := map[string]time.Time{
		"1.0.0": ago(400), "1.1.0": ago(30), "1.2.0-beta.1": ago(10), "1.2.0": ago(1), "2.0.0": ago(0),
	}
	minAge := 3 * 24 * time.Hour
	tests := []struct {
		name     string
		pr       LocalFixProposal
		wantTo   string
		wantHeld bool
	}{
		{"old enough", LocalFixProposal{FromVersion: "1.0.0", ToVersion: "1.1.0"}, "1.1.0", false},
		{"unknown date", LocalFixProposal{FromVersion: "1.0.0", ToVersion: "3.0.0"}, "3.0.0", false},
		{"bump falls back to newest aged stable", LocalFixProposal{FromVersion: "1.0.0", ToVersion: "2.0.0"}, "1.1.0", false},
		{"bump with nothing aged", LocalFixProposal{FromVersion: "1.1.0", ToVersion: "1.2.0"}, "1.2.0", true},
		{"fix is never retargeted", LocalFixProposal{FromVersion: "1.0.0", ToVersion: "1.2.0", VulnerabilityIDs: []string{"GHSA-x"}}, "1.2.0", true},
	}
	for _, tt := range tests {
		pr := tt.pr
		releaseAge(&pr, released, minAge, now)
		if pr.ToVersion != tt.wantTo || pr.TooFresh != tt.wantHeld {
			t.Errorf("%s: got %s too_fresh=%v, want %s too_fresh=%v", tt.name, pr.ToVersion, pr.TooFresh, tt.wantTo, tt.wantHeld)
		}
		if _, known := released[pr.ToVersion]; known && (pr.ReleasedAt == nil || !pr.ReleasedAt.Equal(released[pr.ToVersion])) {
			t.Errorf("%s: released_at %v", tt.name, pr.ReleasedAt)
		}
	}
	kev := LocalFixProposal{VulnerabilityIDs: []string{"CVE-1"}, InKev: true}
	if !securityBeatsCaution(kev) || securityBeatsCaution(LocalFixProposal{Priority: 100}) || securityBeatsCaution(LocalFixProposal{VulnerabilityIDs: []string{"CVE-1"}, Priority: 100}) || !securityBeatsCaution(LocalFixProposal{VulnerabilityIDs: []string{"MAL-1"}, Malicious: true}) {
		t.Error("securityBeatsCaution")
	}
}

func TestSecurityProposalsTransitive(t *testing.T) {
	finding := func(pkg, version, fixed, vuln string, path ...string) dbq.ListFixableFindingsRow {
		return dbq.ListFixableFindingsRow{ProjectID: 1, Direct: len(path) == 1, PackageName: pkg, PackageVersion: version,
			FixedVersion: fixed, VulnerabilityID: vuln, Severity: "high", DependencyPath: path, Via: path[:1]}
	}
	findings := []dbq.ListFixableFindingsRow{
		finding("express", "4.17.1", "4.19.2", "GHSA-direct", "express"),
		finding("qs", "6.7.0", "6.10.3", "GHSA-qs", "express", "qs"),                       // parent bump above the direct fix: max wins
		finding("cookie", "0.4.0", "0.7.0", "GHSA-cookie", "express", "cookie"),            // no parent version: override
		finding("minimist", "1.2.0", "1.2.6", "GHSA-mini", "mocha", "mkdirp", "minimist"),  // depth 3: override
		finding("minimist", "1.2.0", "1.2.8", "GHSA-mini2", "mocha", "mkdirp", "minimist"), // merged, max fixed version
		finding("lodash", "4.17.20", "4.17.21", "GHSA-lodash", "express", "lodash"),        // also a direct root dep: skipped
	}
	direct := map[int64]map[string]dbq.ListScanPackagesRow{1: {
		"express": {Name: "express", Version: "4.17.1", Direct: true},
		"mocha":   {Name: "mocha", Version: "10.0.0", Direct: true, Dev: true},
	}}
	var calls []string
	parentBump := func(parent, from, child, fixed string) (string, bool) {
		calls = append(calls, parent+"@"+from+">"+child+"@"+fixed)
		if child == "qs" {
			return "4.20.0", true
		}
		return "", false
	}
	got := securityProposals(findings, map[int64]string{1: ""}, map[string][]string{"express": {""}, "lodash": {""}}, direct, parentBump)
	if len(got) != 3 {
		t.Fatalf("proposals: %+v", got)
	}
	bump, cookie, mini := got[0], got[1], got[2]
	if bump.Kind != "bump" || bump.PackageName != "express" || bump.FromVersion != "4.17.1" || bump.ToVersion != "4.20.0" ||
		!reflect.DeepEqual(bump.VulnerabilityIDs, []string{"GHSA-direct", "GHSA-qs"}) || !reflect.DeepEqual(bump.Transitive, []string{"qs"}) {
		t.Errorf("parent bump: %+v", bump)
	}
	if cookie.Kind != "override" || cookie.ManifestDir != "" || cookie.PackageName != "cookie" || cookie.ToVersion != "0.7.0" || !reflect.DeepEqual(cookie.Via, []string{"express"}) {
		t.Errorf("cookie override: %+v", cookie)
	}
	if mini.Kind != "override" || mini.ToVersion != "1.2.8" || !reflect.DeepEqual(mini.VulnerabilityIDs, []string{"GHSA-mini", "GHSA-mini2"}) || !reflect.DeepEqual(mini.Via, []string{"mocha"}) {
		t.Errorf("minimist override: %+v", mini)
	}
	if want := []string{"express@4.17.1>qs@6.10.3", "express@4.17.1>cookie@0.7.0", "express@4.17.1>lodash@4.17.21"}; !reflect.DeepEqual(calls, want) {
		t.Errorf("ParentBump calls %v, want %v (depth 3 must not ask)", calls, want)
	}
	if len(lowRisk([]LocalFixProposal{cookie})) != 0 {
		t.Error("an override is never low risk")
	}
	if e := overrideEffort(estimateEffort("0.4.0", "0.4.1", false, nil, "cookie")); e.Effort != "medium" {
		t.Errorf("override effort %+v", e)
	}
}

func TestCommitOverride(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{\n  \"dependencies\": {\n    \"express\": \"^4.17.1\"\n  },\n  \"overrides\": {\n    \"cookie\": \"0.5.0\"\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	if _, err := wt.Add("package.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit("init", &git.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@t", When: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	fixes := []dbq.LocalFix{
		{Kind: "override", PackageName: "cookie", FromVersion: "0.4.0", ToVersion: "0.7.0", VulnerabilityIds: []string{"GHSA-cookie"}},
		{Kind: "override", PackageName: "minimist", FromVersion: "1.2.0", ToVersion: "1.2.8"},
		{Kind: "bump", PackageName: "express", FromVersion: "4.17.1", ToVersion: "4.20.0"},
	}
	msg := localFixMessage(fixes[:1], "npm")
	if !strings.HasPrefix(msg, "fix(deps): override cookie from 0.4.0 to 0.7.0 (transitive, pinned with overrides in the root package.json)\n") {
		t.Errorf("message %q", msg)
	}
	_, commit, err := commitFixes(dir, "fix/override-cookie-0.7.0", "npm", msg, fixes)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := repo.CommitObject(plumbing.NewHash(commit))
	f, err := c.File("package.json")
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"dependencies\": {\n    \"express\": \"^4.20.0\"\n  },\n  \"overrides\": {\n    \"cookie\": \"0.7.0\",\n    \"minimist\": \"1.2.8\"\n  }\n}\n"
	if got, _ := f.Contents(); got != want {
		t.Errorf("package.json = %q, want %q", got, want)
	}
}
