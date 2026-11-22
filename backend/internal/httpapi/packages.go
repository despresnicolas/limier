package httpapi

import "net/http"

// searchPackages answers "Where is this package?" (F5.x); the app validates q.
func (s *Server) searchPackages(w http.ResponseWriter, r *http.Request) {
	res, err := s.app.SearchPackages(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
