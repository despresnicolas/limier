package httpapi

import (
	"net/http"
	"time"
)

func (s *Server) dashboardSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projects, err := s.q.DashboardCounts(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sev, err := s.q.DashboardSeverityCounts(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	top, err := s.q.TopRiskProjects(ctx, 10)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	trend, err := s.q.GlobalTrend(ctx, time.Now().AddDate(0, 0, -90))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	bySeverity := map[string]int32{"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
	var kev, malicious int32
	for _, c := range sev {
		bySeverity[c.Severity] = c.Count
		kev += c.InKev
		malicious += c.Malicious
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"counts":                      map[string]int32{"projects": projects},
		"vulnerabilities_by_severity": bySeverity,
		"vulnerabilities_in_kev":      kev,
		"vulnerabilities_malicious":   malicious,
		"top_risk_projects":           orEmpty(top),
		"trend":                       orEmpty(trend),
	})
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
