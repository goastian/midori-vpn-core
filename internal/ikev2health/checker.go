// Package ikev2health verifies the strongSwan control plane through its
// private VICI socket. A listening UDP port or a live process is not enough:
// the expected IKEv2 connection must also be loaded in charon.
package ikev2health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	StatusFile    = "/run/midorivpn-health/ikev2.json"
	MaxStatusAge  = 15 * time.Second
	maxStatusSize = 4096
)

type Status struct {
	OK        bool      `json:"ok"`
	IKEv2     bool      `json:"ikev2"`
	CheckedAt time.Time `json:"checked_at"`
}

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

// Publish atomically replaces the health status after a successful VICI
// query. Core mounts the parent directory read-only.
func Publish(path string, checkedAt time.Time) error {
	if path != StatusFile {
		return errors.New("invalid IKEv2 health status path")
	}
	return publish(path, checkedAt)
}

func publish(path string, checkedAt time.Time) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".ikev2-health-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	status := Status{OK: true, IKEv2: true, CheckedAt: checkedAt.UTC()}
	if err := json.NewEncoder(temporary).Encode(status); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

// ReadFresh rejects symlinks, writable status files, stale timestamps and any
// state that was not produced after a successful real VICI query.
func ReadFresh(path string, now time.Time) error {
	if path != StatusFile {
		return errors.New("invalid IKEv2 health status path")
	}
	return readFresh(path, now)
}

func readFresh(path string, now time.Time) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || info.Size() < 1 || info.Size() > maxStatusSize {
		return errors.New("invalid IKEv2 health status file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(content), maxStatusSize))
	decoder.DisallowUnknownFields()
	var status Status
	if err := decoder.Decode(&status); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid trailing IKEv2 health status data")
	}
	if !status.OK || !status.IKEv2 || status.CheckedAt.IsZero() {
		return errors.New("IKEv2 control plane is unhealthy")
	}
	age := now.Sub(status.CheckedAt)
	if age < -5*time.Second || age > MaxStatusAge {
		return errors.New("IKEv2 health status is stale")
	}
	return nil
}
