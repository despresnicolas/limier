package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Health tells how well a package is looked after (SPECS "santé d'un paquet"). Nil fields are unknown.
type Health struct {
	Scorecard   *float64 // OpenSSF Scorecard overall score (0–10) of the source repository, from deps.dev
	Maintainers *int     // npm maintainers of the version
	Repository  string   // source repository as an https URL (see RepoURL), "" when unknown
}

// PackageHealth fetches the health of one package version: the npm version document gives the
// maintainers, and deps.dev gives the source repository then its Scorecard. Each source may fail
// on its own; it only leaves its field nil.
func (c *Client) PackageHealth(ctx context.Context, name, version string) Health {
	var h Health
	if raw, err := c.getBytes(ctx, "GET", c.ep.NPM+"/"+npmEscape(name)+"/"+url.PathEscape(version), nil, nil, maxBodySize); err == nil {
		if n, err := parseMaintainers(raw); err == nil {
			h.Maintainers = &n
		}
	}
	raw, err := c.getBytes(ctx, "GET", c.ep.DepsDev+"/v3/systems/npm/packages/"+url.QueryEscape(name)+"/versions/"+url.QueryEscape(version), nil, nil, maxBodySize)
	if err != nil {
		return h
	}
	repo, link := parseSourceRepo(raw)
	if h.Repository = RepoURL(repo); h.Repository == "" {
		h.Repository = RepoURL(link)
	}
	if repo == "" {
		return h
	}
	if raw, err := c.getBytes(ctx, "GET", c.ep.DepsDev+"/v3/projects/"+url.QueryEscape(repo), nil, nil, maxBodySize); err == nil {
		h.Scorecard, _ = parseScorecard(raw)
	}
	return h
}

// PackageHealths fetches the health of many packages (name -> version) with at most 8 in flight.
func (c *Client) PackageHealths(ctx context.Context, versions map[string]string) map[string]Health {
	out := make(map[string]Health, len(versions))
	var mu sync.Mutex
	names := make([]string, 0, len(versions))
	for n := range versions {
		names = append(names, n)
	}
	forEach(ctx, names, func(n string) {
		h := c.PackageHealth(ctx, n, versions[n])
		mu.Lock()
		out[n] = h
		mu.Unlock()
	})
	return out
}

// parseMaintainers counts the maintainers of an npm version document.
func parseMaintainers(raw []byte) (int, error) {
	var doc struct {
		Maintainers []json.RawMessage `json:"maintainers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("vulndb: npm version: decode: %w", err)
	}
	return len(doc.Maintainers), nil
}

// parseSourceRepo returns the deps.dev project id ("github.com/o/r") of a version's source repository
// and its raw SOURCE_REPO link (the npm "repository" field, any host), each "" when absent.
func parseSourceRepo(raw []byte) (project, link string) {
	var doc struct {
		Links []struct {
			Label string `json:"label"`
			URL   string `json:"url"`
		} `json:"links"`
		RelatedProjects []struct {
			ProjectKey struct {
				ID string `json:"id"`
			} `json:"projectKey"`
			RelationType string `json:"relationType"`
		} `json:"relatedProjects"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return "", ""
	}
	for _, p := range doc.RelatedProjects {
		if p.RelationType == "SOURCE_REPO" {
			project = p.ProjectKey.ID
			break
		}
	}
	for _, l := range doc.Links {
		if l.Label == "SOURCE_REPO" {
			link = l.URL
			break
		}
	}
	return project, link
}

// hostRe is a DNS host name with at least one dot and a top-level label starting with a letter:
// no port, credentials or IP address.
var hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$`)

// RepoURL normalises a repository reference from package metadata (git+https://h/o/r.git, git://,
// ssh://git@h/o/r, git@h:o/r, github:o/r, gitlab:o/r, bitbucket:o/r, or a deps.dev id h/o/r) to
// https://h/o/r. It returns "" for anything else: the result is shown as a link, so only https
// URLs with a plain host name pass.
func RepoURL(raw string) string {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "git+")
	for short, host := range map[string]string{"github:": "github.com/", "gitlab:": "gitlab.com/", "bitbucket:": "bitbucket.org/"} {
		if rest, ok := strings.CutPrefix(s, short); ok {
			s = host + rest
		}
	}
	if rest, ok := strings.CutPrefix(s, "git@"); ok && !strings.Contains(s, "://") { // scp-like git@host:o/r
		s = strings.Replace(rest, ":", "/", 1)
	}
	for _, scheme := range []string{"https://", "http://", "git://", "ssh://"} {
		if rest, ok := strings.CutPrefix(s, scheme); ok {
			s = rest
			break
		}
	}
	if strings.Contains(s, "://") {
		return ""
	}
	u, err := url.Parse("https://" + s)
	if err != nil || u.User != nil && u.User.Username() != "git" || u.Port() != "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	path := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
	if !hostRe.MatchString(host) || strings.Count(path, "/") < 2 {
		return ""
	}
	return (&url.URL{Scheme: "https", Host: host, Path: path}).String()
}

// parseScorecard returns the overall OpenSSF Scorecard score of a deps.dev project, nil when unscored.
func parseScorecard(raw []byte) (*float64, error) {
	var doc struct {
		Scorecard *struct {
			OverallScore *float64 `json:"overallScore"`
		} `json:"scorecard"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("vulndb: deps.dev project: decode: %w", err)
	}
	if doc.Scorecard == nil {
		return nil, nil
	}
	return doc.Scorecard.OverallScore, nil
}
