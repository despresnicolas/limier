package vulndb

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestParentBump(t *testing.T) {
	docs := map[string]string{
		"/npm/parent":       "testdata/npm-parentbump-parent.json",
		"/npm/@sc%2fparent": "testdata/npm-parentbump-scoped-parent.json",
		"/npm/@sc%2fchild":  "testdata/npm-parentbump-child.json",
	}
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "" {
			t.Errorf("no Accept header")
		}
		f, ok := docs[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, f)
	}))
	cases := []struct {
		name, parent, from, fixed, want string
		ok                              bool
	}{
		{"found", "parent", "1.1.0", "1.4.1", "1.3.0", true},
		{"lowest match still vulnerable", "parent", "1.1.0", "1.4.0", "1.3.0", true},
		{"prerelease and deprecated skipped, child dropped", "parent", "1.2.0", "2.0.0", "2.0.0", true},
		{"nothing above", "parent", "2.0.0", "1.4.1", "", false},
		{"scoped, tag skipped, optional and hyphen range", "@sc/parent", "1.0.0", "1.5.0", "1.2.0", true},
		{"none", "@sc/parent", "1.0.0", "2.0.0", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			to, ok, err := c.ParentBump(context.Background(), tc.parent, tc.from, "@sc/child", tc.fixed)
			if err != nil || to != tc.want || ok != tc.ok {
				t.Fatalf("got %q %v %v, want %q %v", to, ok, err, tc.want, tc.ok)
			}
		})
	}
	if _, _, err := c.ParentBump(context.Background(), "missing", "1.0.0", "@sc/child", "1.0.0"); err == nil {
		t.Fatal("want error for unknown parent")
	}
	if _, _, err := c.ParentBump(context.Background(), "parent", "latest", "@sc/child", "1.0.0"); err == nil {
		t.Fatal("want error for non-semver parentFrom")
	}
}

// express 4.17.1 pins qs 6.7.0, 4.17.2 pins 6.9.6, 4.17.3 pins 6.9.7 (CVE-2022-24999 fix).
func TestParentBumpLive(t *testing.T) {
	if os.Getenv("VULNDB_LIVE") != "1" {
		t.Skip("set VULNDB_LIVE=1 to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	to, ok, err := New(Endpoints{}, nil).ParentBump(ctx, "express", "4.17.1", "qs", "6.9.7")
	if err != nil || !ok || to != "4.17.3" {
		t.Fatalf("got %q %v %v, want 4.17.3", to, ok, err)
	}
}
