package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PackageInfo summarises npm registry metadata for one package.
type PackageInfo struct {
	Name       string
	Latest     string               // dist-tags.latest
	Deprecated map[string]string    // version -> deprecation message (only deprecated versions)
	ReleasedAt map[string]time.Time // version -> publish time when known (from deps.dev)
}

// NPMPackage fetches metadata for an npm package. Latest and Deprecated come
// from the registry's abbreviated metadata (Accept:
// application/vnd.npm.install-v1+json); per-version publish times come from
// deps.dev GET /v3/systems/npm/packages/{name}. A deps.dev failure is
// tolerated and leaves ReleasedAt empty. Scoped names ("@scope/name") are
// requested as registry/@scope%2fname. An unknown package yields an error
// wrapping ErrNotFound.
func (c *Client) NPMPackage(ctx context.Context, name string) (PackageInfo, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return PackageInfo{}, fmt.Errorf("vulndb: npm: empty package name")
	}
	info := PackageInfo{Name: name, Deprecated: map[string]string{}, ReleasedAt: map[string]time.Time{}}

	hdr := http.Header{"Accept": {"application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8"}}
	raw, err := c.getBytes(ctx, "GET", c.ep.NPM+"/"+npmEscape(name), nil, hdr, maxBodySize)
	if err != nil {
		return PackageInfo{}, err
	}
	var doc struct {
		Name     string            `json:"name"`
		DistTags map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Deprecated json.RawMessage `json:"deprecated"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return PackageInfo{}, fmt.Errorf("vulndb: npm %s: decode: %w", name, err)
	}
	info.Latest = doc.DistTags["latest"]
	for v, m := range doc.Versions {
		var msg string
		if len(m.Deprecated) > 0 && json.Unmarshal(m.Deprecated, &msg) == nil && msg != "" {
			info.Deprecated[v] = msg
		}
	}

	if times, err := c.depsDevVersions(ctx, name); err == nil {
		info.ReleasedAt = times
	}
	return info, nil
}

// npmEscape returns the registry path for a package name: "@scope/name"
// becomes "@scope%2fname".
func npmEscape(name string) string {
	if strings.HasPrefix(name, "@") {
		if scope, pkg, ok := strings.Cut(name[1:], "/"); ok {
			return "@" + url.PathEscape(scope) + "%2f" + url.PathEscape(pkg)
		}
	}
	return url.PathEscape(name)
}

func (c *Client) depsDevVersions(ctx context.Context, name string) (map[string]time.Time, error) {
	raw, err := c.getBytes(ctx, "GET", c.ep.DepsDev+"/v3/systems/npm/packages/"+url.QueryEscape(name), nil, nil, maxBodySize)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Versions []struct {
			VersionKey struct {
				Version string `json:"version"`
			} `json:"versionKey"`
			PublishedAt string `json:"publishedAt"`
			IsDefault   bool   `json:"isDefault"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("vulndb: deps.dev %s: decode: %w", name, err)
	}
	out := make(map[string]time.Time, len(doc.Versions))
	for _, v := range doc.Versions {
		if v.VersionKey.Version == "" || v.PublishedAt == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, v.PublishedAt); err == nil {
			out[v.VersionKey.Version] = t
		}
	}
	return out, nil
}

// NPMPackages fetches many packages concurrently (at most 8 in flight).
// Successful lookups are returned in the first map, failures in the second,
// both keyed by package name.
func (c *Client) NPMPackages(ctx context.Context, names []string) (map[string]PackageInfo, map[string]error) {
	ok := make(map[string]PackageInfo, len(names))
	failed := map[string]error{}
	var mu sync.Mutex
	list := uniq(names)
	forEach(ctx, list, func(n string) {
		info, err := c.NPMPackage(ctx, n)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failed[n] = err
		} else {
			ok[n] = info
		}
	})
	if err := ctx.Err(); err != nil {
		for _, n := range list {
			if _, done := ok[n]; !done {
				if _, f := failed[n]; !f {
					failed[n] = err
				}
			}
		}
	}
	return ok, failed
}
