package repo

import (
	"regexp"
	"testing"
)

func TestMaskIPRemovesExactAddressAndKeepsCorrelationStable(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantPrefix string
	}{
		{name: "ipv4", input: "192.0.2.55", wantPrefix: "192.0.2.x ["},
		{name: "ipv6", input: "2001:db8:abcd:12::55", wantPrefix: "2001:db8:abcd:12::x ["},
	}
	hashSuffix := regexp.MustCompile(`\[[0-9a-f]{8}\]$`)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := maskIP(test.input)
			second := maskIP("  " + test.input + "  ")
			if first != second {
				t.Fatalf("mask is not stable: %q != %q", first, second)
			}
			if len(first) <= len(test.wantPrefix) || first[:len(test.wantPrefix)] != test.wantPrefix {
				t.Fatalf("masked IP = %q, want prefix %q", first, test.wantPrefix)
			}
			if !hashSuffix.MatchString(first) {
				t.Fatalf("masked IP lacks correlation suffix: %q", first)
			}
			if first == test.input {
				t.Fatalf("exact IP escaped masking: %q", first)
			}
		})
	}
}

func TestMaskIPPreservesSentinels(t *testing.T) {
	for _, value := range []string{"", "system"} {
		if got := maskIP(value); got != value {
			t.Fatalf("maskIP(%q) = %q", value, got)
		}
	}
}

func TestListSQLHelpersUseAllowlistedDirection(t *testing.T) {
	if got := listWhere(nil); got != "" {
		t.Fatalf("empty WHERE = %q", got)
	}
	if got := listWhere([]string{"active = TRUE", "name = $1"}); got != " WHERE active = TRUE AND name = $1" {
		t.Fatalf("WHERE = %q", got)
	}
	if got := listDirection("asc"); got != "ASC" {
		t.Fatalf("ascending direction = %q", got)
	}
	for _, untrusted := range []string{"ASC", "desc", "asc; DROP TABLE users"} {
		if got := listDirection(untrusted); got != "DESC" {
			t.Fatalf("listDirection(%q) = %q, want DESC", untrusted, got)
		}
	}
}
