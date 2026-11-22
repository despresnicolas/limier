package vulndb

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := New(Endpoints{OSV: srv.URL, KEV: srv.URL + "/kev.json", EPSS: srv.URL + "/epss.csv.gz", DepsDev: srv.URL + "/depsdev", NPM: srv.URL + "/npm"}, srv.Client())
	c.baseWait = time.Millisecond
	return c, srv
}

func TestNewDefaults(t *testing.T) {
	c := New(Endpoints{}, nil)
	if c.ep.OSV != DefaultOSV || c.ep.KEV != DefaultKEV || c.ep.DepsDev != DefaultDepsDev || c.ep.NPM != DefaultNPM {
		t.Fatalf("defaults not applied: %+v", c.ep)
	}
	if len(c.epssURLs) != 2 || c.epssURLs[0] != DefaultEPSS || c.epssURLs[1] != LegacyEPSS {
		t.Fatalf("epss urls: %v", c.epssURLs)
	}
}

func TestQueryBatchSplitAndPagination(t *testing.T) {
	var (
		mu    sync.Mutex
		sizes []int
	)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" || r.Method != "POST" {
			http.Error(w, "bad", 400)
			return
		}
		if r.Header.Get("User-Agent") != "limier/1.0" {
			http.Error(w, "ua", 400)
			return
		}
		var req struct {
			Queries []osvQuery `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mu.Lock()
		sizes = append(sizes, len(req.Queries))
		mu.Unlock()
		type vuln struct {
			ID string `json:"id"`
		}
		type result struct {
			Vulns []vuln `json:"vulns,omitempty"`
			Next  string `json:"next_page_token,omitempty"`
		}
		var resp struct {
			Results []result `json:"results"`
		}
		for _, q := range req.Queries {
			var res result
			name := q.Package.Name
			if q.Package.Purl != "" {
				name = q.Package.Purl
			}
			switch {
			case name == "pkg:npm/lodash@4.17.20" && q.PageToken == "":
				res = result{Vulns: []vuln{{"GHSA-1"}}, Next: "p2"}
			case name == "pkg:npm/lodash@4.17.20" && q.PageToken == "p2":
				res = result{Vulns: []vuln{{"GHSA-2"}, {"GHSA-1"}}}
			case name == "pkg-1500":
				res = result{Vulns: []vuln{{"OSV-1500"}}}
			}
			resp.Results = append(resp.Results, res)
		}
		json.NewEncoder(w).Encode(resp)
	})
	c, _ := newTestClient(t, h)

	qs := make([]PackageQuery, 2001)
	for i := range qs {
		qs[i] = PackageQuery{Ecosystem: "npm", Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0"}
	}
	qs[5] = PackageQuery{Purl: "pkg:npm/lodash@4.17.20"}
	got, err := c.QueryBatch(context.Background(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(qs) {
		t.Fatalf("len %d", len(got))
	}
	if want := []string{"GHSA-1", "GHSA-2"}; fmt.Sprint(got[5]) != fmt.Sprint(want) {
		t.Errorf("got[5]=%v want %v", got[5], want)
	}
	if fmt.Sprint(got[1500]) != "[OSV-1500]" {
		t.Errorf("got[1500]=%v", got[1500])
	}
	if got[0] != nil {
		t.Errorf("got[0]=%v", got[0])
	}
	if fmt.Sprint(sizes) != "[1000 1000 1 1]" {
		t.Errorf("batch sizes %v", sizes)
	}
}

func TestRetryOn5xxAnd429(t *testing.T) {
	var n atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			w.WriteHeader(503)
		case 2:
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
		default:
			w.Write([]byte(`{"id":"GHSA-x"}`))
		}
	}))
	b, err := c.GetVuln(context.Background(), "GHSA-x")
	if err != nil || string(b) != `{"id":"GHSA-x"}` {
		t.Fatalf("b=%s err=%v", b, err)
	}
	if n.Load() != 3 {
		t.Errorf("attempts %d", n.Load())
	}
}

func TestRetryExhausted(t *testing.T) {
	var n atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Error(w, "boom", 502)
	}))
	_, err := c.GetVuln(context.Background(), "X")
	var he *HTTPError
	if !errors.As(err, &he) || he.StatusCode != 502 {
		t.Fatalf("err=%v", err)
	}
	if n.Load() != 1+maxRetries {
		t.Errorf("attempts %d", n.Load())
	}
}

func TestGetVulns(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == "MISSING" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"id":%q}`, id)
	}))
	ids := []string{"A", "B", "MISSING", "A"}
	for i := range 20 {
		ids = append(ids, fmt.Sprintf("V%d", i))
	}
	got, err := c.GetVulns(context.Background(), ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 22 {
		t.Fatalf("len %d", len(got))
	}
	if _, ok := got["MISSING"]; ok {
		t.Error("MISSING present")
	}
	if string(got["B"]) != `{"id":"B"}` {
		t.Errorf("B=%s", got["B"])
	}
}

func TestFetchKEV(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"title":"CISA KEV","catalogVersion":"2026.10.21","count":2,"vulnerabilities":[
		 {"cveID":"CVE-2021-44228","vendorProject":"Apache","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"},
		 {"cveID":"CVE-2024-0001","dateAdded":"2024-01-02","knownRansomwareCampaignUse":"Unknown"},
		 {"cveID":"","dateAdded":"2024-01-02"}]}`)
	}))
	got, err := c.FetchKEV(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len %d", len(got))
	}
	want0 := KEVEntry{CVE: "CVE-2021-44228", DateAdded: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC), Ransomware: true}
	if got[0] != want0 {
		t.Errorf("got %+v", got[0])
	}
	if got[1].Ransomware || got[1].CVE != "CVE-2024-0001" {
		t.Errorf("got %+v", got[1])
	}
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	io.WriteString(w, s)
	w.Close()
	return b.Bytes()
}

const epssCSV = "#model_version:v2026.06.15,score_date:2026-10-21T12:00:15Z\n" +
	"cve,epss,percentile\n" +
	"CVE-1999-0001,0.04753,0.91832\n" +
	"CVE-2021-44228,0.94400,0.99990\n" +
	"garbage,row\n"

func TestFetchEPSS(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(gz(epssCSV))
	}))
	var got []EPSSScore
	if err := c.FetchEPSS(context.Background(), func(s EPSSScore) error { got = append(got, s); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []EPSSScore{{"CVE-1999-0001", 0.04753, 0.91832}, {"CVE-2021-44228", 0.944, 0.9999}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v", got)
	}
}

func TestFetchEPSSPlainAndCallbackError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, epssCSV)
	}))
	stop := errors.New("stop")
	n := 0
	err := c.FetchEPSS(context.Background(), func(EPSSScore) error { n++; return stop })
	if !errors.Is(err, stop) || n != 1 {
		t.Fatalf("err=%v n=%d", err, n)
	}
}

func TestFetchEPSSFallback(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(gz(epssCSV)) }))
	defer good.Close()
	c := New(Endpoints{}, nil)
	c.epssURLs = []string{bad.URL, good.URL}
	n := 0
	if err := c.FetchEPSS(context.Background(), func(EPSSScore) error { n++; return nil }); err != nil || n != 2 {
		t.Fatalf("err=%v n=%d", err, n)
	}
}

func TestNPMPackageScopedAndDepsDev(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/npm/"):
			if r.URL.RawPath != "/npm/@types%2fnode" {
				http.Error(w, "raw path "+r.URL.RawPath, 400)
				return
			}
			if !strings.Contains(r.Header.Get("Accept"), "application/vnd.npm.install-v1+json") {
				http.Error(w, "accept", 400)
				return
			}
			io.WriteString(w, `{"name":"@types/node","dist-tags":{"latest":"22.1.0","next":"23.0.0-rc"},
			  "versions":{"1.0.0":{"deprecated":"too old"},"22.1.0":{},"2.0.0":{"deprecated":""}}}`)
		case strings.HasPrefix(r.URL.Path, "/depsdev/v3/systems/npm/packages/"):
			if r.URL.EscapedPath() != "/depsdev/v3/systems/npm/packages/%40types%2Fnode" {
				http.Error(w, "deps path "+r.URL.EscapedPath(), 400)
				return
			}
			io.WriteString(w, `{"packageKey":{"system":"NPM","name":"@types/node"},"versions":[
			  {"versionKey":{"system":"NPM","name":"@types/node","version":"1.0.0"},"publishedAt":"2016-11-28T16:30:56Z","isDefault":false},
			  {"versionKey":{"system":"NPM","name":"@types/node","version":"22.1.0"},"publishedAt":"2024-08-01T10:00:00Z","isDefault":true}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	info, err := c.NPMPackage(context.Background(), "@types/node")
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "@types/node" || info.Latest != "22.1.0" {
		t.Errorf("info %+v", info)
	}
	if len(info.Deprecated) != 1 || info.Deprecated["1.0.0"] != "too old" {
		t.Errorf("deprecated %v", info.Deprecated)
	}
	if !info.ReleasedAt["22.1.0"].Equal(time.Date(2024, 8, 1, 10, 0, 0, 0, time.UTC)) || len(info.ReleasedAt) != 2 {
		t.Errorf("released %v", info.ReleasedAt)
	}
}

func TestNPMPackageDepsDevFailureTolerated(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/npm/") {
			io.WriteString(w, `{"name":"left-pad","dist-tags":{"latest":"1.3.0"},"versions":{"1.3.0":{"deprecated":"use String.prototype.padStart()"}}}`)
			return
		}
		http.Error(w, "down", 500)
	}))
	info, err := c.NPMPackage(context.Background(), "left-pad")
	if err != nil {
		t.Fatal(err)
	}
	if info.Latest != "1.3.0" || len(info.ReleasedAt) != 0 || info.Deprecated["1.3.0"] == "" {
		t.Errorf("info %+v", info)
	}
}

func TestNPMPackages(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/nope" {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/npm/") {
			fmt.Fprintf(w, `{"dist-tags":{"latest":"1.0.0"},"versions":{}}`)
			return
		}
		http.NotFound(w, r)
	}))
	ok, failed := c.NPMPackages(context.Background(), []string{"a", "b", "nope", "a"})
	if len(ok) != 2 || len(failed) != 1 || !errors.Is(failed["nope"], ErrNotFound) {
		t.Fatalf("ok=%v failed=%v", ok, failed)
	}
}

func TestNPMEscape(t *testing.T) {
	for in, want := range map[string]string{"lodash": "lodash", "@babel/core": "@babel%2fcore"} {
		if got := npmEscape(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestVersionsBehind(t *testing.T) {
	cases := []struct{ inst, latest, want string }{
		{"1.2.3", "2.0.0", "major"},
		{"1.2.3", "1.3.0", "minor"},
		{"1.2.3", "1.2.4", "patch"},
		{"1.2.3", "1.2.3", ""},
		{"2.0.0", "1.9.9", ""},
		{"1.2.3-beta.1", "1.2.3", "patch"},
		{"v0.9.0", "1.0.0", "major"},
		{"latest", "1.0.0", ""},
		{"1.0.0", "", ""},
	}
	for _, c := range cases {
		if got := VersionsBehind(c.inst, c.latest); got != c.want {
			t.Errorf("VersionsBehind(%q,%q)=%q want %q", c.inst, c.latest, got, c.want)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	lr := &limitedReader{r: strings.NewReader("abcdef"), n: 3, url: "x"}
	_, err := io.ReadAll(lr)
	if err == nil {
		t.Fatal("expected limit error")
	}
}
