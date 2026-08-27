package ikev2health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckerRequiresLoadedConnection(t *testing.T) {
	directory := t.TempDir()
	command := filepath.Join(directory, "swanctl")
	script := "#!/bin/sh\ncase \"$1\" in\n  --stats) echo uptime: 1s ;;\n  --list-conns) echo 'midori-ikev2: version = 2' ;;\n  *) exit 2 ;;\nesac\n"
	if err := os.WriteFile(command, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	checker := Checker{SwanctlPath: command, VICISocket: "/run/test.vici", Connection: "midori-ikev2"}
	if err := checker.Healthy(context.Background()); err != nil {
		t.Fatalf("Healthy() error = %v", err)
	}
}

func TestCheckerRejectsMissingConnection(t *testing.T) {
	directory := t.TempDir()
	command := filepath.Join(directory, "swanctl")
	if err := os.WriteFile(command, []byte("#!/bin/sh\necho 'different-connection'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	checker := Checker{SwanctlPath: command, VICISocket: "/run/test.vici", Connection: "midori-ikev2"}
	if err := checker.Healthy(context.Background()); err == nil {
		t.Fatal("Healthy() accepted a daemon without the configured IKEv2 connection")
	}
}

func TestStatusPublishAndFreshness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ikev2.json")
	now := time.Date(2026, 8, 27, 2, 0, 0, 0, time.UTC)
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
	path := filepath.Join(directory, "ikev2.json")
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
	if err := os.WriteFile(target, []byte(`{"ok":true,"ikev2":true,"checked_at":"2026-08-27T02:00:00Z"}`), 0o644); err != nil {
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
	path := filepath.Join(t.TempDir(), "ikev2.json")
	if err := Publish(path, time.Now()); err == nil {
		t.Fatal("Publish accepted a non-private path")
	}
	if err := ReadFresh(path, time.Now()); err == nil {
		t.Fatal("ReadFresh accepted a non-private path")
	}
}
