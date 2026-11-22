package httpapi

import "net/http"

// getSettings returns the app settings that background jobs read (watch_vulns: SPECS F3.8).
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.q.GetAppSettings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"watch_vulns": st.WatchVulns})
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		WatchVulns *bool `json:"watch_vulns"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.WatchVulns == nil {
		writeError(w, http.StatusBadRequest, "watch_vulns is required")
		return
	}
	if err := s.q.SetWatchVulns(r.Context(), *body.WatchVulns); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"watch_vulns": *body.WatchVulns})
}
