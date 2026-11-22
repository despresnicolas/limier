// Package vulndb fetches vulnerability and package metadata from public
// sources: OSV (vulnerabilities), CISA KEV (known exploited CVEs), FIRST EPSS
// (exploit prediction scores), the npm registry and deps.dev (outdated and
// deprecated dependencies).
package vulndb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default endpoints.
const (
	DefaultOSV     = "https://api.osv.dev"
	DefaultKEV     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSS    = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	DefaultDepsDev = "https://api.deps.dev"
	DefaultNPM     = "https://registry.npmjs.org"

	// LegacyEPSS is the historical EPSS location (now redirecting to
	// DefaultEPSS). It is tried as a fallback when Endpoints.EPSS is unset.
	LegacyEPSS = "https://epss.cyentia.com/epss_scores-current.csv.gz"
)

const (
	userAgent       = "limier/1.0"
	maxBodySize     = 20 << 20 // 20 MiB for JSON documents
	maxEPSSSize     = 50 << 20 // 50 MiB for the compressed EPSS feed
	maxRetries      = 3
	concurrency     = 8
	defaultTimeout  = 60 * time.Second
	maxRetryAfter   = 30 * time.Second
	defaultBaseWait = 500 * time.Millisecond
)

// ErrNotFound is returned (wrapped) when an upstream answers 404.
var ErrNotFound = errors.New("vulndb: not found")

// Endpoints holds the base URLs of the upstream services. Empty fields fall
// back to the Default* constants.
type Endpoints struct {
	OSV     string // default "https://api.osv.dev"
	KEV     string // default CISA KEV JSON feed
	EPSS    string // default "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	DepsDev string // default "https://api.deps.dev"
	NPM     string // default "https://registry.npmjs.org"
}

// Client talks to the upstream services. It sets the "limier/1.0" User-Agent,
// applies timeouts and retries up to 3 times with exponential backoff on 429
// and 5xx responses as well as transport errors. It is safe for concurrent use.
type Client struct {
	hc       *http.Client
	ep       Endpoints
	epssURLs []string
	baseWait time.Duration
}

// New returns a Client. Zero fields of e use the defaults; a nil hc uses an
// http.Client with a 60s timeout.
func New(e Endpoints, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	c := &Client{hc: hc, baseWait: defaultBaseWait}
	if e.EPSS == "" {
		c.epssURLs = []string{DefaultEPSS, LegacyEPSS}
		e.EPSS = DefaultEPSS
	} else {
		c.epssURLs = []string{e.EPSS}
	}
	e.OSV = orDefault(e.OSV, DefaultOSV)
	e.KEV = orDefault(e.KEV, DefaultKEV)
	e.DepsDev = orDefault(e.DepsDev, DefaultDepsDev)
	e.NPM = orDefault(e.NPM, DefaultNPM)
	c.ep = e
	return c
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return strings.TrimRight(v, "/")
}

// HTTPError describes a non-2xx upstream response.
type HTTPError struct {
	Method, URL string
	StatusCode  int
	Body        string // truncated
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("vulndb: %s %s: HTTP %d", e.Method, e.URL, e.StatusCode)
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

// Unwrap maps 404 to ErrNotFound so errors.Is works.
func (e *HTTPError) Unwrap() error {
	if e.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	return nil
}

// do performs the request with retries and returns the response with a 2xx
// status. The caller must close the body. body may be nil.
func (c *Client) do(ctx context.Context, method, url string, body []byte, hdr http.Header) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			wait := c.baseWait << (attempt - 1)
			var he *retryAfterErr
			if errors.As(lastErr, &he) && he.after > 0 {
				wait = min(he.after, maxRetryAfter)
			}
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rd)
		if err != nil {
			return nil, fmt.Errorf("vulndb: build request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		for k, v := range hdr {
			req.Header[k] = v
		}
		if body != nil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("vulndb: %s %s: %w", method, url, err)
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		herr := &HTTPError{Method: method, URL: url, StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(snippet))}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = &retryAfterErr{HTTPError: herr, after: parseRetryAfter(resp.Header.Get("Retry-After"))}
			continue
		}
		return nil, herr
	}
	var ra *retryAfterErr
	if errors.As(lastErr, &ra) {
		return nil, ra.HTTPError
	}
	return nil, lastErr
}

type retryAfterErr struct {
	*HTTPError
	after time.Duration
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

// getBytes performs a request and reads the whole body up to limit bytes.
func (c *Client) getBytes(ctx context.Context, method, url string, body []byte, hdr http.Header, limit int64) ([]byte, error) {
	resp, err := c.do(ctx, method, url, body, hdr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("vulndb: read %s: %w", url, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("vulndb: %s: response exceeds %d bytes", url, limit)
	}
	return b, nil
}

// limitedReader is like io.LimitReader but returns an error when the limit is
// exceeded instead of a silent EOF.
type limitedReader struct {
	r   io.Reader
	n   int64
	url string
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		// Probe for extra data.
		var one [1]byte
		if n, _ := l.r.Read(one[:]); n > 0 {
			return 0, fmt.Errorf("vulndb: %s: response exceeds size limit", l.url)
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// forEach runs fn over items with bounded concurrency, stopping early when
// ctx is cancelled.
func forEach[T any](ctx context.Context, items []T, fn func(T)) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, it := range items {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(it)
		}(it)
	}
	wg.Wait()
}
