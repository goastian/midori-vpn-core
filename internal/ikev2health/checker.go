// Package ikev2health verifies the strongSwan control plane through its
// private VICI socket. A listening UDP port or a live process is not enough:
// the expected IKEv2 connection must also be loaded in charon.
package ikev2health

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Checker struct {
	SwanctlPath string
	VICISocket  string
	Connection  string
}

func (c Checker) Healthy(ctx context.Context) error {
	if strings.TrimSpace(c.SwanctlPath) == "" || strings.TrimSpace(c.VICISocket) == "" || strings.TrimSpace(c.Connection) == "" {
		return errors.New("IKEv2 health checker configuration is incomplete")
	}
	uri := "unix://" + c.VICISocket
	if _, err := c.run(ctx, "--stats", "--uri", uri); err != nil {
		return fmt.Errorf("query strongSwan statistics: %w", err)
	}
	connections, err := c.run(ctx, "--list-conns", "--raw", "--uri", uri)
	if err != nil {
		return fmt.Errorf("list strongSwan connections: %w", err)
	}
	if !strings.Contains(connections, c.Connection) {
		return fmt.Errorf("strongSwan connection %q is not loaded", c.Connection)
	}
	return nil
}

func (c Checker) run(parent context.Context, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, c.SwanctlPath, arguments...)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
