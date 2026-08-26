package openvpnhealth

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckerRequiresManagementStatusAndDCOMarker(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "management.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = connection.Write([]byte(">INFO:OpenVPN Management Interface Version 6 -- type 'help' for more info\n"))
		buffer := make([]byte, 64)
		_, _ = connection.Read(buffer)
		_, _ = connection.Write([]byte("SUCCESS: nclients=0,bytesin=0,bytesout=0\n"))
	}()
	logPath := filepath.Join(dir, "openvpn.log")
	if err := os.WriteFile(logPath, []byte("DCO device lo opened\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checker := Checker{ManagementSocket: socket, LogPath: logPath, InterfaceName: "lo"}
	if err := checker.Healthy(context.Background()); err != nil {
		t.Fatalf("Healthy() error = %v", err)
	}
}

func TestCheckerRejectsMissingDCOMarker(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "openvpn.log")
	if err := os.WriteFile(logPath, []byte("Initialization Sequence Completed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checker := Checker{ManagementSocket: "/missing", LogPath: logPath, InterfaceName: "lo"}
	if err := checker.Healthy(context.Background()); err == nil {
		t.Fatal("Healthy() accepted a gateway without DCO evidence")
	}
}
