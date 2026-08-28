package openvpnhealth

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestCheckerKeepsInitialDCOMarkerAfterLogGrowth(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "openvpn.log")
	content := append([]byte("DCO device lo opened\n"), make([]byte, 300*1024)...)
	if err := os.WriteFile(logPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	checker := Checker{LogPath: logPath, InterfaceName: "lo"}
	if err := checker.requireDCOLogMarker(); err != nil {
		t.Fatalf("initial DCO marker was lost after log growth: %v", err)
	}
}

func TestStatusPublishAndFreshness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openvpn.json")
	now := time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC)
	if err := publish(path, now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("status mode = %o", info.Mode().Perm())
	}
	if err := readFresh(path, now.Add(5*time.Second)); err != nil {
		t.Fatalf("fresh status rejected: %v", err)
	}
	if err := readFresh(path, now.Add(MaxStatusAge+time.Second)); err == nil {
		t.Fatal("stale status accepted")
	}
}

func TestStatusReaderRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "openvpn.json")
	now := time.Now().UTC()
	if err := publish(path, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := readFresh(path, now); err == nil {
		t.Fatal("writable status accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(`{"ok":true,"dco":true,"checked_at":"2026-08-28T02:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := readFresh(path, now); err == nil {
		t.Fatal("symlinked status accepted")
	}
}

func TestPublicStatusFunctionsRequireFixedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openvpn.json")
	if err := Publish(path, time.Now()); err == nil {
		t.Fatal("Publish accepted a non-private path")
	}
	if err := ReadFresh(path, time.Now()); err == nil {
		t.Fatal("ReadFresh accepted a non-private path")
	}
}
