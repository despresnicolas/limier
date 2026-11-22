package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"limier/internal/db/dbq"
	"limier/internal/fixbot"
	"limier/internal/policy"
)

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	parent, err := queryInt64(r, "parent_id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	roots := parent == nil
	if v, err := queryBool(r, "roots_only"); err == nil && v != nil {
		roots = *v
	}
	sort := r.URL.Query().Get("sort")
	if sort == "" {
		sort = "path"
	}
	rows, err := s.q.ListProjects(r.Context(), dbq.ListProjectsParams{
		Limit: limit, Offset: offset, Search: queryString(r, "search"),
		ParentID: parent, RootsOnly: &roots, Sort: sort,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page[dbq.ListProjectsRow]{Items: rows, Total: total(rows, func(r dbq.ListProjectsRow) int64 { return r.Total })})
}

// rootOf returns the project holding scans: the monorepo parent for a workspace.
func (s *Server) rootOf(r *http.Request) (dbq.Project, error) {
	id, _ := strconv.ParseInt(chiParam(r, "projectID"), 10, 64)
	p, err := s.q.GetProject(r.Context(), id)
	if err != nil || p.ParentID == nil {
		return p, err
	}
	return s.q.GetProject(r.Context(), *p.ParentID)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, _ := pathID(w, r, "projectID")
	p, err := s.q.GetProject(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scans, err := s.q.LatestScanPerKind(ctx, root.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sev, err := s.q.ProjectSeverityCounts(ctx, root.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var metrics *dbq.CodeMetric
	if root.LastCodeScanID != nil {
		if m, err := s.q.GetCodeMetrics(ctx, *root.LastCodeScanID); err == nil {
			metrics = &m
		}
	}
	workspaces, err := s.q.ListWorkspaces(ctx, &root.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"project":         p,
		"root_project_id": root.ID,
		"latest_scans":    scans,
		"vulnerabilities": sev,
		"security_grade":  policy.SecurityGrade(root.RiskScore),
		"code_metrics":    metrics,
		"workspaces":      workspaces,
	})
}

func (s *Server) getProjectPolicy(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var rules policy.Rules
	if pol, err := s.q.GetPolicy(r.Context(), dbq.GetPolicyParams{Scope: "project", ProjectID: &root.ID}); err == nil {
		rules, _ = policy.ParseRules(pol.Rules)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "effective": s.app.EffectiveRules(r.Context(), root.ID)})
}

func (s *Server) putProjectPolicy(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.savePolicy(w, r, "project", &root.ID)
}

// putBranchPrefix sets the first segment of fix branches; workspaces use their root's.
func (s *Server) putBranchPrefix(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var body struct {
		BranchPrefix string `json:"branch_prefix"`
	}
	if !decode(w, r, &body) {
		return
	}
	prefix := strings.Trim(strings.TrimSpace(body.BranchPrefix), "/")
	if err := fixbot.ValidBranchPrefix(prefix); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.q.SetProjectBranchPrefix(r.Context(), dbq.SetProjectBranchPrefixParams{ID: root.ID, BranchPrefix: prefix}); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"branch_prefix": prefix})
}

func (s *Server) savePolicy(w http.ResponseWriter, r *http.Request, scope string, projectID *int64) {
	var rules policy.Rules
	if !decode(w, r, &rules) {
		return
	}
	if err := rules.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, _ := json.Marshal(rules)
	pol, err := s.q.UpsertPolicy(r.Context(), dbq.UpsertPolicyParams{Scope: scope, ProjectID: projectID, Rules: raw})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var recompute int64
	if projectID != nil {
		recompute = *projectID
	}
	// Weights may have changed: re-score findings.
	if err := s.app.EnqueueRecompute(r.Context(), recompute); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pol)
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit, offset := pagination(r)
	scans, err := s.q.ListProjectScans(r.Context(), dbq.ListProjectScansParams{ProjectID: root.ID, Limit: limit, Offset: offset, Kind: queryString(r, "kind")})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind string `json:"kind"`
	}
	if !decode(w, r, &body) {
		return
	}
	id, _ := pathID(w, r, "projectID")
	scan, err := s.app.EnqueueScan(r.Context(), id, body.Kind, "manual")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, scan)
}

type dependencyView struct {
	dbq.ListScanPackagesRow
	Outdated string `json:"outdated,omitempty"`
	TooOld   bool   `json:"too_old"`
	// DeclaredIn lists the manifest directories declaring a direct dependency ("" is the root).
	DeclaredIn []string `json:"declared_in,omitempty"`
}

func (s *Server) listDependencies(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if root.LastDepsScanID == nil {
		writeJSON(w, http.StatusOK, []dependencyView{})
		return
	}
	rows, err := s.q.ListScanPackages(r.Context(), *root.LastDepsScanID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rules := s.app.EffectiveRules(r.Context(), root.ID)
	declared := s.app.DeclaredIn(r.Context(), root)
	directOnly, _ := queryBool(r, "direct")
	out := make([]dependencyView, 0, len(rows))
	for _, row := range rows {
		if directOnly != nil && row.Direct != *directOnly {
			continue
		}
		v := dependencyView{ListScanPackagesRow: row}
		if row.Direct {
			v.DeclaredIn = declared[row.Name]
		}
		if row.LatestVersion != "" {
			v.Outdated = versionsBehind(row.Version, row.LatestVersion)
		}
		if row.ReleasedAt != nil && rules.MaxDependencyAgeDays > 0 {
			v.TooOld = time.Since(*row.ReleasedAt) > time.Duration(rules.MaxDependencyAgeDays)*24*time.Hour
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) codeMetrics(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit, _ := pagination(r)
	rows, err := s.q.ListCodeMetricsHistory(r.Context(), dbq.ListCodeMetricsHistoryParams{ProjectID: root.ID, Limit: limit})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) projectTrends(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	days := 90
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v > 0 {
		days = min(v, 730)
	}
	rows, err := s.q.ProjectTrend(r.Context(), dbq.ProjectTrendParams{ProjectID: root.ID, Day: time.Now().AddDate(0, 0, -days)})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// exportSBOM returns the CycloneDX JSON of the latest dependency scan, or of ?scan_id= (F6.4).
func (s *Server) exportSBOM(w http.ResponseWriter, r *http.Request) {
	root, err := s.rootOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scanID := root.LastDepsScanID
	if v, err := queryInt64(r, "scan_id"); err == nil && v != nil {
		scan, err := s.q.GetScan(r.Context(), *v)
		if err != nil || scan.ProjectID != root.ID {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		scanID = v
	}
	if scanID == nil {
		writeError(w, http.StatusNotFound, "no SBOM yet")
		return
	}
	sb, err := s.q.GetSBOMByScan(r.Context(), *scanID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	doc, err := s.app.Store().Get(r.Context(), sb.StorageUri)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sbom-project-%d-scan-%d.cdx.json"`, root.ID, *scanID))
	_, _ = w.Write(doc)
}

func (s *Server) getGlobalPolicy(w http.ResponseWriter, r *http.Request) {
	pol, err := s.q.GetPolicy(r.Context(), dbq.GetPolicyParams{Scope: "global"})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": pol, "effective": s.app.EffectiveRules(r.Context(), 0)})
}

func (s *Server) putGlobalPolicy(w http.ResponseWriter, r *http.Request) {
	s.savePolicy(w, r, "global", nil)
}

// openInEditor opens a file of the project at a line in the user's editor (code findings).
func (s *Server) openInEditor(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "projectID")
	if !ok {
		return
	}
	var body struct {
		Editor string `json:"editor"`
		File   string `json:"file"`
		Line   int    `json:"line"`
	}
	if !decode(w, r, &body) {
		return
	}
	p, err := s.q.GetProject(r.Context(), id)
	if err == nil {
		err = s.app.OpenInEditor(p, body.Editor, body.File, body.Line)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
