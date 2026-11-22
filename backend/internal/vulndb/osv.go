package vulndb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync"
)

// osvBatchLimit is the maximum number of queries per /v1/querybatch request.
const osvBatchLimit = 1000

// PackageQuery identifies a package version to look up in OSV, either by
// Purl (which should include the version, e.g. "pkg:npm/lodash@4.17.20") or
// by Ecosystem+Name+Version (e.g. "npm", "lodash", "4.17.20").
type PackageQuery struct {
	Purl      string
	Ecosystem string
	Name      string
	Version   string
}

type osvQuery struct {
	Package   osvPackage `json:"package"`
	Version   string     `json:"version,omitempty"`
	PageToken string     `json:"page_token,omitempty"`
}

type osvPackage struct {
	Purl      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
}

type osvBatchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

func (q PackageQuery) toOSV() osvQuery {
	if q.Purl != "" {
		return osvQuery{Package: osvPackage{Purl: q.Purl}}
	}
	return osvQuery{Package: osvPackage{Ecosystem: q.Ecosystem, Name: q.Name}, Version: q.Version}
}

// QueryBatch queries OSV's POST /v1/querybatch. Queries are split into
// requests of at most 1000 and per-query pagination (next_page_token) is
// followed. The result is aligned with qs: result[i] holds the deduplicated
// vulnerability IDs affecting qs[i] (nil when none).
func (c *Client) QueryBatch(ctx context.Context, qs []PackageQuery) ([][]string, error) {
	out := make([][]string, len(qs))
	type pending struct {
		idx int
		q   osvQuery
	}
	todo := make([]pending, len(qs))
	for i, q := range qs {
		todo[i] = pending{idx: i, q: q.toOSV()}
	}
	seen := make([]map[string]struct{}, len(qs))
	for len(todo) > 0 {
		var next []pending
		for chunk := range slices.Chunk(todo, osvBatchLimit) {
			req := struct {
				Queries []osvQuery `json:"queries"`
			}{Queries: make([]osvQuery, len(chunk))}
			for i, p := range chunk {
				req.Queries[i] = p.q
			}
			body, err := json.Marshal(req)
			if err != nil {
				return nil, fmt.Errorf("vulndb: osv querybatch: %w", err)
			}
			raw, err := c.getBytes(ctx, "POST", c.ep.OSV+"/v1/querybatch", body, nil, maxBodySize)
			if err != nil {
				return nil, err
			}
			var resp osvBatchResp
			if err := json.Unmarshal(raw, &resp); err != nil {
				return nil, fmt.Errorf("vulndb: osv querybatch: decode: %w", err)
			}
			if len(resp.Results) != len(chunk) {
				return nil, fmt.Errorf("vulndb: osv querybatch: got %d results for %d queries", len(resp.Results), len(chunk))
			}
			for i, r := range resp.Results {
				p := chunk[i]
				for _, v := range r.Vulns {
					if v.ID == "" {
						continue
					}
					if seen[p.idx] == nil {
						seen[p.idx] = map[string]struct{}{}
					}
					if _, dup := seen[p.idx][v.ID]; dup {
						continue
					}
					seen[p.idx][v.ID] = struct{}{}
					out[p.idx] = append(out[p.idx], v.ID)
				}
				if r.NextPageToken != "" && r.NextPageToken != p.q.PageToken {
					nq := p.q
					nq.PageToken = r.NextPageToken
					next = append(next, pending{idx: p.idx, q: nq})
				}
			}
		}
		todo = next
	}
	return out, nil
}

// GetVuln fetches GET /v1/vulns/{id} and returns the raw OSV JSON document.
// A missing id yields an error wrapping ErrNotFound.
func (c *Client) GetVuln(ctx context.Context, id string) ([]byte, error) {
	return c.getBytes(ctx, "GET", c.ep.OSV+"/v1/vulns/"+url.PathEscape(id), nil, nil, maxBodySize)
}

// GetVulns fetches many vulnerabilities concurrently (at most 8 in flight)
// and returns id -> raw JSON. Unknown ids (404) are skipped silently; other
// failures are skipped too and reported joined in the returned error, which
// accompanies the partial map.
func (c *Client) GetVulns(ctx context.Context, ids []string) (map[string][]byte, error) {
	res := make(map[string][]byte, len(ids))
	var (
		mu   sync.Mutex
		errs []error
	)
	forEach(ctx, uniq(ids), func(id string) {
		b, err := c.GetVuln(ctx, id)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			res[id] = b
		case errors.Is(err, ErrNotFound):
		default:
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
		}
	})
	if err := ctx.Err(); err != nil {
		errs = append(errs, err)
	}
	return res, errors.Join(errs...)
}

func uniq(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; ok || v == "" {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
