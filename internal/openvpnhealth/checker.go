// Package openvpnhealth verifies that an OpenVPN gateway is initialized,
// reachable through its management socket and running with kernel DCO.
package openvpnhealth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const maxManagementResponse = 1 << 20

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
	const tailSize = int64(256 * 1024)
	if info.Size() > tailSize {
		if _, err := file.Seek(-tailSize, io.SeekEnd); err != nil {
			return fmt.Errorf("seek OpenVPN log: %w", err)
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, tailSize))
	if err != nil {
		return fmt.Errorf("read OpenVPN log: %w", err)
	}
	marker := "DCO device " + c.InterfaceName + " opened"
	if !strings.Contains(string(data), marker) {
		return errors.New("openvpn DCO initialization marker is absent")
	}
	return nil
}
