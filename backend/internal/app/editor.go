package app

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"limier/internal/db/dbq"
)

// editorSchemes lists the URL schemes of the editors the UI offers; anything else is refused.
// VS Code, VSCodium and Cursor document <scheme>://file/<path>:<line>.
// JetBrains IDEs register <ide>://open?file=…&line=… on install (or through Toolbox):
// shortcut: these schemes are not formally documented by JetBrains, switch to jetbrains://<ide>/navigate/reference if they break.
var editorSchemes = map[string]bool{
	"vscode": true, "vscodium": true, "cursor": true,
	"idea": true, "webstorm": true, "phpstorm": true, "pycharm": true,
	"goland": true, "rubymine": true, "rider": true, "clion": true,
}

// EditorURL returns the URL that opens file (relative to the project folder) at line in editor.
// The file must be a regular file inside the project folder: the path comes from the webview.
func (a *App) EditorURL(p dbq.Project, editor, file string, line int) (string, error) {
	if !editorSchemes[editor] {
		return "", fmt.Errorf("%w: unknown editor %q", ErrInvalid, editor)
	}
	rel, err := a.resolveLocal(p.LocalPath)
	if err != nil {
		return "", err
	}
	file = filepath.FromSlash(file)
	if !filepath.IsLocal(file) {
		return "", fmt.Errorf("%w: the file is outside the project", ErrInvalid)
	}
	dir := filepath.Join(a.cfg.LocalReposRoot, filepath.FromSlash(rel))
	abs, err := filepath.Abs(filepath.Join(dir, file))
	if err != nil {
		return "", err
	}
	// A symlink inside the project could point anywhere.
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("%w: file not found", ErrInvalid)
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	if r, err := filepath.Rel(realDir, real); err != nil || !filepath.IsLocal(r) {
		return "", fmt.Errorf("%w: the file is outside the project", ErrInvalid)
	}
	if st, err := os.Stat(real); err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("%w: not a file", ErrInvalid)
	}
	line = max(line, 1)
	path := filepath.ToSlash(abs)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path // Windows: C:/x becomes /C:/x
	}
	switch editor {
	case "vscode", "vscodium", "cursor":
		return (&url.URL{Scheme: editor, Host: "file", Path: fmt.Sprintf("%s:%d", path, line)}).String(), nil
	default:
		// QueryEscape writes spaces as "+", which the IDEs keep literally.
		return fmt.Sprintf("%s://open?file=%s&line=%d", editor, strings.ReplaceAll(url.QueryEscape(path), "+", "%20"), line), nil
	}
}

// OpenInEditor opens file at line in editor through the desktop opener.
func (a *App) OpenInEditor(p dbq.Project, editor, file string, line int) error {
	u, err := a.EditorURL(p, editor, file, line)
	if err != nil {
		return err
	}
	if a.openURL == nil {
		return fmt.Errorf("%w: opening an editor is not available", ErrInvalid)
	}
	return a.openURL(u)
}
