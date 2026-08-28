// Package openvpnhealth verifies that an OpenVPN gateway is initialized,
// reachable through its management socket and running with kernel DCO.
package openvpnhealth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	StatusFile            = "/run/midorivpn-health/openvpn.json"
	MaxStatusAge          = 15 * time.Second
	maxStatusSize         = 4096
	maxManagementResponse = 1 << 20
)

type Status struct {
	OK        bool      `json:"ok"`
	DCO       bool      `json:"dco"`
	CheckedAt time.Time `json:"checked_at"`
}

type Checker struct {
	ManagementSocket string
	LogPath          string
	InterfaceName    string
}

func (c Checker) Healthy(ctx context.Context) error {
	if c.ManagementSocket == "" || c.LogPath == "" || c.InterfaceName == "" {
		return errors.New("openvpn health checker configuration is incomplete")
	}
	if _, err := net.InterfaceByName(c.InterfaceName); err != nil {
		return fmt.Errorf("openvpn interface is unavailable: %w", err)
	}
	if err := c.requireDCOLogMarker(); err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", c.ManagementSocket)
	if err != nil {
		return fmt.Errorf("connect to OpenVPN management socket: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(2 * time.Second)
	if requestDeadline, ok := ctx.Deadline(); ok && requestDeadline.Before(deadline) {
		deadline = requestDeadline
	}
	_ = connection.SetDeadline(deadline)
	limited := io.LimitReader(connection, maxManagementResponse)
	reader := bufio.NewReader(limited)
	banner, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, ">INFO:OpenVPN Management Interface Version ") {
		return errors.New("openvpn management banner is invalid")
	}
	if _, err := io.WriteString(connection, "load-stats\n"); err != nil {
		return fmt.Errorf("query OpenVPN management socket: %w", err)
	}
	status, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read OpenVPN management status: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(status), "SUCCESS: nclients=") {
		return errors.New("openvpn management status is incomplete")
	}
	_, _ = io.WriteString(connection, "quit\n")
	return nil
}

func (c Checker) requireDCOLogMarker() error {
	file, err := os.Open(c.LogPath)
	if err != nil {
		return fmt.Errorf("open OpenVPN log: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat OpenVPN log: %w", err)
	}
	const windowSize = int64(256 * 1024)
	data, err := io.ReadAll(io.LimitReader(file, windowSize))
	if err != nil {
		return fmt.Errorf("read OpenVPN log: %w", err)
	}
	marker := "DCO device " + c.InterfaceName + " opened"
	if strings.Contains(string(data), marker) {
		return nil
	}
	if info.Size() > windowSize {
		if _, err := file.Seek(-windowSize, io.SeekEnd); err != nil {
			return fmt.Errorf("seek OpenVPN log: %w", err)
		}
		data, err = io.ReadAll(io.LimitReader(file, windowSize))
		if err != nil {
			return fmt.Errorf("read OpenVPN log tail: %w", err)
		}
	}
	if !strings.Contains(string(data), marker) {
		return errors.New("openvpn DCO initialization marker is absent")
	}
	return nil
}

// Publish atomically replaces the health status after the checker has
// verified the DCO interface and the private management socket.
func Publish(path string, checkedAt time.Time) error {
	if path != StatusFile {
		return errors.New("invalid OpenVPN health status path")
	}
	return publish(path, checkedAt)
}

func publish(path string, checkedAt time.Time) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".openvpn-health-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	status := Status{OK: true, DCO: true, CheckedAt: checkedAt.UTC()}
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

// ReadFresh rejects links, writable files, stale timestamps and status that
// cannot have originated from a successful DCO-aware gateway check.
func ReadFresh(path string, now time.Time) error {
	if path != StatusFile {
		return errors.New("invalid OpenVPN health status path")
	}
	return readFresh(path, now)
}

func readFresh(path string, now time.Time) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || info.Size() < 1 || info.Size() > maxStatusSize {
		return errors.New("invalid OpenVPN health status file")
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
		return errors.New("invalid trailing OpenVPN health status data")
	}
	if !status.OK || !status.DCO || status.CheckedAt.IsZero() {
		return errors.New("OpenVPN control plane is unhealthy")
	}
	age := now.Sub(status.CheckedAt)
	if age < -5*time.Second || age > MaxStatusAge {
		return errors.New("OpenVPN health status is stale")
	}
	return nil
}
