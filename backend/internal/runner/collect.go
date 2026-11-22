package runner

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// extractTar reads a tar stream and records every regular file into c. Entry
// names are interpreted relative to prefix (itself relative to /work).
// Symlinks, devices and other special entries are ignored.
func extractTar(r io.Reader, prefix string, c *collector) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("runner: reading outputs archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		rel := path.Clean(h.Name)
		if path.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") {
			continue // never let an entry escape the requested output
		}
		name := path.Join(prefix, rel)
		err = c.add(name, h.Size, func(limit int64) ([]byte, error) {
			data, err := io.ReadAll(io.LimitReader(tr, limit+1))
			if err != nil {
				return nil, fmt.Errorf("runner: reading output %q: %w", name, err)
			}
			if int64(len(data)) > limit {
				return nil, fmt.Errorf("%w (%d bytes)", ErrOutputTooLarge, c.max)
			}
			return data, nil
		})
		if err != nil {
			return err
		}
	}
}
