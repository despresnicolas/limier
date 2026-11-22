package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// KEVEntry is one entry of the CISA Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVE        string
	DateAdded  time.Time // UTC midnight of the dateAdded day; zero if unparseable
	Ransomware bool      // knownRansomwareCampaignUse == "Known"
}

// FetchKEV downloads and parses the CISA KEV JSON feed.
func (c *Client) FetchKEV(ctx context.Context) ([]KEVEntry, error) {
	raw, err := c.getBytes(ctx, "GET", c.ep.KEV, nil, nil, maxBodySize)
	if err != nil {
		return nil, err
	}
	return parseKEV(raw)
}

func parseKEV(raw []byte) ([]KEVEntry, error) {
	var doc struct {
		Vulnerabilities []struct {
			CveID                      string `json:"cveID"`
			DateAdded                  string `json:"dateAdded"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("vulndb: kev: decode: %w", err)
	}
	out := make([]KEVEntry, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CveID))
		if id == "" {
			continue
		}
		d, _ := time.Parse(time.DateOnly, strings.TrimSpace(v.DateAdded))
		out = append(out, KEVEntry{
			CVE:        id,
			DateAdded:  d,
			Ransomware: strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known"),
		})
	}
	return out, nil
}
