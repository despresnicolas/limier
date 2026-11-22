package vulndb

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLive hits the real upstreams. Run with VULNDB_LIVE=1.
func TestLive(t *testing.T) {
	if os.Getenv("VULNDB_LIVE") != "1" {
		t.Skip("set VULNDB_LIVE=1 to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := New(Endpoints{}, nil)

	ids, err := c.QueryBatch(ctx, []PackageQuery{{Purl: "pkg:npm/lodash@4.17.15"}, {Ecosystem: "npm", Name: "minimist", Version: "1.2.0"}})
	if err != nil || len(ids[0]) == 0 || len(ids[1]) == 0 {
		t.Fatalf("osv: %v %v", ids, err)
	}
	t.Logf("osv lodash@4.17.15: %v", ids[0])
	vulns, err := c.GetVulns(ctx, ids[0])
	if err != nil || len(vulns) == 0 {
		t.Fatalf("getvulns: %d %v", len(vulns), err)
	}

	kev, err := c.FetchKEV(ctx)
	if err != nil || len(kev) < 1000 {
		t.Fatalf("kev: %d %v", len(kev), err)
	}
	t.Logf("kev: %d entries, first %+v", len(kev), kev[0])

	n := 0
	var first EPSSScore
	if err := c.FetchEPSS(ctx, func(s EPSSScore) error {
		if n == 0 {
			first = s
		}
		n++
		return nil
	}); err != nil || n < 100000 {
		t.Fatalf("epss: %d %v", n, err)
	}
	t.Logf("epss: %d rows, first %+v", n, first)

	info, err := c.NPMPackage(ctx, "@types/node")
	if err != nil || info.Latest == "" || len(info.ReleasedAt) == 0 {
		t.Fatalf("npm: %+v %v", info.Latest, err)
	}
	t.Logf("@types/node latest=%s deprecated=%d released=%d (latest at %s)", info.Latest, len(info.Deprecated), len(info.ReleasedAt), info.ReleasedAt[info.Latest])
	rq, err := c.NPMPackage(ctx, "request")
	if err != nil || len(rq.Deprecated) == 0 {
		t.Fatalf("request: %d %v", len(rq.Deprecated), err)
	}
	t.Logf("request latest=%s deprecated[latest]=%q", rq.Latest, rq.Deprecated[rq.Latest])
	h := c.PackageHealth(ctx, "express", "4.21.2")
	if h.Maintainers == nil || h.Scorecard == nil {
		t.Fatalf("health: %+v", h)
	}
	t.Logf("express health: scorecard=%.1f maintainers=%d", *h.Scorecard, *h.Maintainers)
}
