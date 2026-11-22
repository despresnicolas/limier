package runner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// demux splits a Docker multiplexed log stream into stdout and stderr.
//
// Each frame starts with an 8-byte header [stream, 0, 0, 0, size(uint32 BE)]
// followed by size bytes of payload. Stream 0 (stdin) and 1 go to stdout, 2
// goes to stderr; stream 3 (systemerr) is reported as an error.
func demux(r io.Reader, stdout, stderr io.Writer) error {
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading log frame header: %w", err)
		}
		size := int64(binary.BigEndian.Uint32(hdr[4:]))
		var w io.Writer
		switch hdr[0] {
		case 0, 1:
			w = stdout
		case 2:
			w = stderr
		case 3:
			msg, _ := io.ReadAll(io.LimitReader(r, min(size, 4096)))
			return fmt.Errorf("docker system error: %s", msg)
		default:
			return fmt.Errorf("invalid log stream id %d", hdr[0])
		}
		if _, err := io.CopyN(w, r, size); err != nil {
			return fmt.Errorf("reading log frame: %w", err)
		}
	}
}
