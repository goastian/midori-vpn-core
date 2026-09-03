package ippool

import (
	"errors"
	"testing"
)

func TestPoolUsesConfiguredPrefixAndAccurateCapacity(t *testing.T) {
	pool, err := New("10.44.8.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := pool.GatewayIP(); got != "10.44.8.1/24" {
		t.Fatalf("GatewayIP() = %q", got)
	}
	if got := pool.FreeCount(); got != 253 {
		t.Fatalf("initial FreeCount() = %d, want 253", got)
	}
	ip, err := pool.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if ip != "10.44.8.2/32" || pool.FreeCount() != 252 {
		t.Fatalf("allocation = %q free=%d", ip, pool.FreeCount())
	}
}

func TestPoolBounds(t *testing.T) {
	if _, err := New("10.0.0.0/16"); err != nil {
		t.Fatalf("maximum supported pool rejected: %v", err)
	}
	if _, err := New("10.0.0.0/15"); !errors.Is(err, ErrPoolTooLarge) {
		t.Fatalf("oversized pool error = %v", err)
	}
	if _, err := New("10.0.0.0/31"); !errors.Is(err, ErrPoolTooSmall) {
		t.Fatalf("undersized pool error = %v", err)
	}
}

func TestPoolNeverReservesOrReleasesInfrastructureAddresses(t *testing.T) {
	pool, err := New("192.0.2.0/29")
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.0.2.0", "192.0.2.1", "192.0.2.7"} {
		if err := pool.Reserve(address); !errors.Is(err, ErrIPNotUsable) {
			t.Fatalf("Reserve(%q) error = %v", address, err)
		}
		if err := pool.Release(address); !errors.Is(err, ErrIPNotUsable) {
			t.Fatalf("Release(%q) error = %v", address, err)
		}
	}
}
