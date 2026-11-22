// Package nodetools embeds the node-tools Dockerfile, so the desktop app can build the image itself.
package nodetools

import _ "embed"

//go:embed Dockerfile
var Dockerfile []byte
