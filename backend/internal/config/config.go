// Package config holds the settings of the backend embedded in the desktop app.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	// LocalReposRoot is the only directory under which local repositories can be registered.
	LocalReposRoot string

	// DockerHost is the Docker Engine socket used by the scan pipelines.
	DockerHost string
	Images     ToolImages

	WorkerConcurrency int
	LogLevel          string
}

// ToolImages are the container images run by the local fix pipeline.
type ToolImages struct {
	Node string // node tool image: npm/pnpm/yarn and git
}

func Load() (Config, error) {
	c := Config{
		LocalReposRoot: os.Getenv("LOCAL_REPOS_ROOT"),
		DockerHost:     env("DOCKER_HOST", "unix:///var/run/docker.sock"),
		Images: ToolImages{
			Node: env("IMAGE_NODE_TOOLS", "limier/node-tools:latest"),
		},
		WorkerConcurrency: envInt("WORKER_CONCURRENCY", 4),
		LogLevel:          env("LOG_LEVEL", "info"),
	}
	return c, c.validate()
}

func (c Config) validate() error {
	var errs []error
	if c.LocalReposRoot != "" && !filepath.IsAbs(c.LocalReposRoot) {
		errs = append(errs, errors.New("LOCAL_REPOS_ROOT must be an absolute path"))
	}
	if c.WorkerConcurrency < 1 {
		errs = append(errs, errors.New("WORKER_CONCURRENCY must be >= 1"))
	}
	return errors.Join(errs...)
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}
