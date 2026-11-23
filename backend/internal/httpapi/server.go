// Package httpapi exposes the internal REST API used by the app's webview, under /api/v1.
package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"limier/internal/app"
	"limier/internal/config"
	"limier/internal/db/dbq"
)

type Server struct {
	app *app.App
	q   *dbq.Queries
	cfg config.Config
	// userID is the single local user, recorded on fix decisions.
	userID int64
}

// New builds the API served to the app's webview only: it has no authentication of its own.
func New(ctx context.Context, a *app.App) (*Server, error) {
	uid, err := a.LocalUserID(ctx)
	if err != nil {
		return nil, err
	}
	return &Server{app: a, q: a.Queries(), cfg: a.Config(), userID: uid}, nil
}

const maxBody = 1 << 20

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, s.logRequests, middleware.Recoverer, limitBody(maxBody))

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/features", s.features)
		r.Get("/dashboard/summary", s.dashboardSummary)
		r.Get("/packages/drift", s.versionDrift)

		r.Get("/projects", s.listProjects)
		r.Get("/local-projects/browse", s.browseLocal)
		r.Post("/local-projects", s.createLocalProject)
		r.Route("/projects/{projectID}", func(r chi.Router) {
			r.Use(validProjectID)
			r.Get("/", s.getProject)
			r.Delete("/", s.deleteProject)
			r.Get("/policy", s.getProjectPolicy)
			r.Put("/policy", s.putProjectPolicy)
			r.Put("/branch-prefix", s.putBranchPrefix)
			r.Get("/scans", s.listScans)
			r.Post("/scans", s.createScan)
			r.Get("/findings", s.listProjectFindings)
			r.Get("/dependencies", s.listDependencies)
			r.Get("/code-metrics", s.codeMetrics)
			r.Get("/trends", s.projectTrends)
			r.Get("/local-fixes", s.listLocalFixes)
			r.Post("/local-fixes", s.decideLocalFix)
			r.Post("/local-fixes/group", s.groupLocalFixes)
			r.Delete("/local-fixes/{fixID}", s.reopenLocalFix)
			r.Get("/sbom", s.exportSBOM)
			r.Post("/open-in-editor", s.openInEditor)
			r.Put("/false-positives", s.putFalsePositive)
		})

		r.Get("/findings", s.listFindings)
		r.Get("/findings/{findingID}", s.getFinding)

		r.Get("/packages/search", s.searchPackages)

		r.Get("/policies/global", s.getGlobalPolicy)
		r.Put("/policies/global", s.putGlobalPolicy)
		r.Get("/settings", s.getSettings)
		r.Put("/settings", s.putSettings)
	})
	return r
}

// ---- middleware

// validProjectID rejects a malformed {projectID}, so that handlers can read it without checking.
func validProjectID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := pathID(w, r, "projectID"); ok {
			next.ServeHTTP(w, r)
		}
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		next.ServeHTTP(ww, r)
		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		slog.InfoContext(r.Context(), "http request", "method", r.Method, "route", route, "status", ww.Status(),
			"duration_ms", time.Since(start).Milliseconds(), "request_id", middleware.GetReqID(r.Context()))
	})
}

func limitBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// ---- helpers

type page[T any] struct {
	Items []T   `json:"items"`
	Total int64 `json:"total"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// fail maps domain errors to HTTP statuses and hides internal errors.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows), errors.Is(err, app.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, app.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, app.ErrScanInProgress):
		writeError(w, http.StatusConflict, err.Error())
	default:
		slog.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "err", err, "request_id", middleware.GetReqID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid "+name)
		return 0, false
	}
	return id, true
}

// pagination reads limit (default 50, max 500) and offset.
func pagination(r *http.Request) (int32, int32) {
	limit, offset := 50, 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, 500)
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v >= 0 {
		offset = v
	}
	return int32(limit), int32(offset)
}

func queryString(r *http.Request, key string) *string {
	if v := strings.TrimSpace(r.URL.Query().Get(key)); v != "" {
		return &v
	}
	return nil
}

func queryBool(r *http.Request, key string) (*bool, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return nil, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return nil, fmt.Errorf("%s must be a boolean", key)
	}
	return &b, nil
}

func queryInt64(r *http.Request, key string) (*int64, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%s must be an integer", key)
	}
	return &n, nil
}

func queryList(r *http.Request, key string) []string {
	var out []string
	for _, v := range r.URL.Query()[key] {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func total[T any](rows []T, get func(T) int64) int64 {
	if len(rows) == 0 {
		return 0
	}
	return get(rows[0])
}
