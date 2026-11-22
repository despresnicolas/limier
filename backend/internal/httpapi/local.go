package httpapi

import "net/http"

// features tells the UI which optional capabilities are enabled.
func (s *Server) features(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"local_projects": s.cfg.LocalReposRoot != ""})
}

// browseLocal lists the sub-folders of ?path= (relative to LOCAL_REPOS_ROOT) for the folder picker.
func (s *Server) browseLocal(w http.ResponseWriter, r *http.Request) {
	b, err := s.app.BrowseLocal(r.Context(), r.URL.Query().Get("path"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// createLocalProject registers a folder as a project and queues its first scans.
// The path is relative to LOCAL_REPOS_ROOT (or absolute inside it); anything outside is rejected.
func (s *Server) createLocalProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}
	p, err := s.app.RegisterLocalProject(r.Context(), body.Path, body.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// listLocalFixes returns the fixes proposed for a local project and the decisions already taken.
func (s *Server) listLocalFixes(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "projectID")
	if !ok {
		return
	}
	fixes, err := s.app.LocalFixes(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, fixes)
}

// decideLocalFix accepts (a branch is created in the local repository) or rejects a proposal.
// The proposal is identified by manifest directory, package and target version, and must still be current.
func (s *Server) decideLocalFix(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "projectID")
	if !ok {
		return
	}
	var body struct {
		ManifestDir string `json:"manifest_dir"`
		PackageName string `json:"package_name"`
		ToVersion   string `json:"to_version"`
		Decision    string `json:"decision"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Decision != "accept" && body.Decision != "reject" {
		writeError(w, http.StatusBadRequest, `decision must be "accept" or "reject"`)
		return
	}
	if body.PackageName == "" || body.ToVersion == "" {
		writeError(w, http.StatusBadRequest, "package_name and to_version are required")
		return
	}
	uid := s.userID
	fx, err := s.app.DecideLocalFix(r.Context(), id, uid, body.ManifestDir, body.PackageName, body.ToVersion, body.Decision == "accept")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := http.StatusOK
	if body.Decision == "accept" {
		status = http.StatusAccepted
	}
	writeJSON(w, status, fx)
}

// groupLocalFixes accepts all low-risk proposals on one branch.
func (s *Server) groupLocalFixes(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "projectID")
	if !ok {
		return
	}
	fixes, err := s.app.GroupLocalFixes(r.Context(), id, s.userID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, fixes)
}

// reopenLocalFix removes a rejected or failed decision: the fix is proposed again.
func (s *Server) reopenLocalFix(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "projectID")
	if !ok {
		return
	}
	fixID, ok := pathID(w, r, "fixID")
	if !ok {
		return
	}
	if err := s.app.ReopenLocalFix(r.Context(), id, fixID); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "projectID")
	if !ok {
		return
	}
	if err := s.app.DeleteProject(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
