package vulndb

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// EPSSScore is one row of the EPSS feed.
type EPSSScore struct {
	CVE        string
	Score      float64 // probability of exploitation in the next 30 days, 0..1
	Percentile float64 // 0..1
}

// FetchEPSS downloads the daily EPSS feed (gzip CSV whose first line is a
// "#model_version:...,score_date:..." comment followed by the header
// "cve,epss,percentile") and streams each row to fn, so callers can insert in
// batches without holding the ~300k rows in memory. An error returned by fn
// aborts the download and is returned as is. When Endpoints.EPSS is unset,
// the legacy cyentia URL is tried if the primary URL fails before any row has
// been delivered.
func (c *Client) FetchEPSS(ctx context.Context, fn func(EPSSScore) error) error {
	var errs []error
	for _, u := range c.epssURLs {
		delivered := false
		err := c.fetchEPSS(ctx, u, func(s EPSSScore) error {
			delivered = true
			return fn(s)
		})
		if err == nil {
			return nil
		}
		var cbErr *callbackErr
		if errors.As(err, &cbErr) {
			return cbErr.err
		}
		if delivered || ctx.Err() != nil {
			return err
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

type callbackErr struct{ err error }

func (e *callbackErr) Error() string { return e.err.Error() }

func (c *Client) fetchEPSS(ctx context.Context, u string, fn func(EPSSScore) error) error {
	resp, err := c.do(ctx, "GET", u, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return parseEPSS(&limitedReader{r: resp.Body, n: maxEPSSSize, url: u}, fn)
}

// parseEPSS parses a (possibly gzip-compressed) EPSS CSV stream.
func parseEPSS(r io.Reader, fn func(EPSSScore) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var src io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("vulndb: epss: gzip: %w", err)
		}
		defer gz.Close()
		src = gz
	}
	cr := csv.NewReader(src)
	cr.Comment = '#'
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	line := 0
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("vulndb: epss: csv: %w", err)
		}
		line++
		if len(rec) < 3 {
			continue
		}
		cve := strings.TrimSpace(rec[0])
		if strings.EqualFold(cve, "cve") {
			continue // header
		}
		score, err1 := strconv.ParseFloat(strings.TrimSpace(rec[1]), 64)
		pct, err2 := strconv.ParseFloat(strings.TrimSpace(rec[2]), 64)
		if cve == "" || err1 != nil || err2 != nil {
			continue // skip malformed rows
		}
		if err := fn(EPSSScore{CVE: strings.ToUpper(cve), Score: score, Percentile: pct}); err != nil {
			return &callbackErr{err: err}
		}
	}
	if line == 0 {
		return errors.New("vulndb: epss: empty feed")
	}
	return nil
}
