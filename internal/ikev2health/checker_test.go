package ikev2health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
