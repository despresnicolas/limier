package app

import (
	"context"
	"errors"
	"testing"

	"github.com/Masterminds/semver/v3"

	"limier/internal/db/dbq"
	"limier/internal/scanners"
)

func TestParsePackageQuery(t *testing.T) {
	cases := []struct {
		in, name, version string
		isRange           bool
	}{
		{"axios", "axios", "", false},
		{"  ax ", "ax", "", false},
		{"axios@1.6.0", "axios", "1.6.0", false},
		{"axios@<1.7.0", "axios", "", true},
		{"axios@^1.6", "axios", "", true},
		{"axios@>=1.0.0 <1.7.0", "axios", "", true},
		{"@babel/core@7.24.0", "@babel/core", "7.24.0", false},
		{"@babel/core@~7.24", "@babel/core", "", true},
		{"@babel/core", "@babel/core", "", false},
		{"@babel", "@babel", "", false},
	}
	for _, c := range cases {
		q, err := ParsePackageQuery(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if q.Name != c.name || q.Version != c.version || (q.Range != nil) != c.isRange {
			t.Errorf("%q: got %+v", c.in, q)
		}
	}
	r, _ := ParsePackageQuery("axios@<1.7.0")
	for v, want := range map[string]bool{"1.6.0": true, "1.7.0": false} {
		if got := r.Range.Check(semver.MustParse(v)); got != want {
			t.Errorf("<1.7.0 on %s: got %v", v, got)
		}
	}
	for _, bad := range []string{"", "   ", "axios@", "axios@not a range!", "a%b", "a b", "@scope/name/x", string(make([]byte, 300))} {
		if _, err := ParsePackageQuery(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: want ErrInvalid, got %v", bad, err)
		}
	}
}

func TestDBSearchPackages(t *testing.T) {
	a, _ := dbApp(t)
	ctx := context.Background()
	p, err := a.q.UpsertLocalProject(ctx, dbq.UpsertLocalProjectParams{LocalPath: "grp/app", Path: "grp/app", PackageManager: "npm"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.q.CreateScan(ctx, dbq.CreateScanParams{ProjectID: p.ID, Kind: "deps", Trigger: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	pkgs := map[string]*pkgRef{
		"express@4.17.1": {Ecosystem: "npm", Name: "express", Version: "4.17.1", Direct: true, Path: []string{"express"}},
		"qs@6.7.0":       {Ecosystem: "npm", Name: "qs", Version: "6.7.0", Path: []string{"express", "qs"}},
	}
	if err := a.processDeps(ctx, p, s, pkgs, map[string][]scanners.OSVVuln{"express@4.17.1": {osvRecord(t, expressVuln)}}); err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]int{"EXPR": 1, "s": 2, "x_": 0, "qs@6.7.0": 1, "qs@6.7.1": 0, "express@<5": 1, "express@^5": 0, "expres@4.17.1": 0} {
		res, err := a.SearchPackages(ctx, q)
		if err != nil || len(res.Items) != want {
			t.Errorf("%q: got %d items (%v), want %d", q, len(res.Items), err, want)
		}
	}
	res, _ := a.SearchPackages(ctx, "express")
	if h := res.Items[0]; h.OpenVulns != 1 || h.WorstSeverity != "critical" || !h.Direct || h.ProjectID != p.ID {
		t.Errorf("express hit: %+v", h)
	}
}
