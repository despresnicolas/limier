package app

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestIsPermanentDockerDown(t *testing.T) {
	down := fmt.Errorf("runner: creating volume: %w", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
	if !isPermanent(down) {
		t.Error("docker socket refused should be permanent")
	}
	if isPermanent(fmt.Errorf("npm registry: %w", syscall.ETIMEDOUT)) {
		t.Error("timeouts should be retried")
	}
}
