package httpapi

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"limier/internal/db/dbq"
	"limier/internal/vulndb"
)

func chiParam(r *http.Request, name string) string { return chi.URLParam(r, name) }

func versionsBehind(installed, latest string) string { return vulndb.VersionsBehind(installed, latest) }

// findingFilters reads F5.3 filters: severity, priority, status, direct, kev, malicious, new, search.
func findingFilters(r *http.Request) (dbq.ListFindingsParams, error) {
	limit, offset := pagination(r)
	p := dbq.ListFindingsParams{Limit: limit, Offset: offset, Search: queryString(r, "search")}
	if st := queryString(r, "status"); st != nil {
		if *st != "open" && *st != "fixed" {
			return p, fmt.Errorf("status must be open or fixed")
		}
		p.Status = st
	}
	if sev := queryList(r, "severity"); len(sev) > 0 {
		p.Severities = sev
	} else {
		p.Severities = nil
	}
	if v := r.URL.Query().Get("min_priority"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return p, fmt.Errorf("min_priority must be a number")
		}
		p.MinPriority = &f
	}
	var err error
	if p.Direct, err = queryBool(r, "direct"); err != nil {
		return p, err
	}
	if p.InKev, err = queryBool(r, "kev"); err != nil {
		return p, err
	}
	if p.Malicious, err = queryBool(r, "malicious"); err != nil {
		return p, err
	}
	if p.IsNew, err = queryBool(r, "new"); err != nil {
		return p, err
	}
	return p, nil
}

func (s *Server) listProjectFindings(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeFindings(w, r, &root.ID)
}

// listFindings lists findings across projects.
func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	s.writeFindings(w, r, nil)
}

func (s *Server) writeFindings(w http.ResponseWriter, r *http.Request, projectID *int64) {
	params, err := findingFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	params.ProjectID = projectID
	csvOut := r.URL.Query().Get("format") == "csv"
	if csvOut {
		params.Limit, params.Offset = 100000, 0
	}
	rows, err := s.q.ListFindings(r.Context(), params)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if csvOut {
		writeFindingsCSV(w, rows)
		return
	}
	writeJSON(w, http.StatusOK, page[dbq.ListFindingsRow]{Items: rows, Total: total(rows, func(r dbq.ListFindingsRow) int64 { return r.Total })})
}

// writeFindingsCSV exports vulnerabilities (F6.4). Cells starting with formula characters are escaped.
func writeFindingsCSV(w http.ResponseWriter, rows []dbq.ListFindingsRow) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="limier-findings.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"project", "vulnerability", "aliases", "severity", "cvss", "epss", "kev", "priority", "package",
		"version", "fixed_version", "direct", "dependency_path", "status", "first_seen_at", "summary"})
	for _, f := range rows {
		row := []string{
			f.ProjectPath, f.VulnerabilityID, strings.Join(f.Aliases, " "), f.Severity, fmtFloat(f.CvssScore), fmtFloat(f.EpssScore),
			strconv.FormatBool(f.InKev), strconv.FormatFloat(f.Priority, 'f', 1, 64), f.PackageName, f.PackageVersion,
			f.FixedVersion, strconv.FormatBool(f.Direct), strings.Join(f.DependencyPath, " > "), f.Status,
			f.FirstSeenAt.Format(time.RFC3339), f.Summary,
		}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}

func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func fmtFloat(f *float64) string {
	if f == nil {
		return ""
	}
	return strconv.FormatFloat(*f, 'f', -1, 64)
}

// loadFinding returns the finding after checking the caller's role on its project.
func (s *Server) loadFinding(w http.ResponseWriter, r *http.Request) (dbq.GetFindingRow, bool) {
	id, ok := pathID(w, r, "findingID")
	if !ok {
		return dbq.GetFindingRow{}, false
	}
	f, err := s.q.GetFinding(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return f, false
	}
	return f, true
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	if f, ok := s.loadFinding(w, r); ok {
		writeJSON(w, http.StatusOK, f)
	}
}
