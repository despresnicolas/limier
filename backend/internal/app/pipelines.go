package app

// Pipelines run untrusted repositories: dependency installs always use --ignore-scripts,
// containers are non-root with a read-only root filesystem (enforced by the runner),
// and steps get network access only when they need it.

const (
	srcDir = "/work/src"
	outDir = "/work/out"
)
