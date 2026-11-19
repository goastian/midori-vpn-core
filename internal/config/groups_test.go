package config

import "testing"

func TestWSMaxForGroupsUsesOnlyVPNAdminGroup(t *testing.T) {
	cfg := &Config{
		WSMaxFree: 1, WSMaxBasic: 2, WSMaxMedium: 3,
		WSMaxPro: 5, WSMaxAdmin: 7,
	}
	for _, test := range []struct {
		name   string
		groups []string
		want   int
	}{
		{"missing", nil, 1},
		{"vpn user", []string{"vpn-users"}, 1},
		{"vpn admin", []string{"vpn-admins"}, 7},
		{"global admins", []string{"admins"}, 1},
		{"authentik admins", []string{"authentik Admins"}, 1},
		{"global admin with pro plan", []string{"admins", "plan-pro"}, 5},
		{"basic plan", []string{"plan-basic"}, 2},
		{"medium plan", []string{"plan-medium"}, 3},
		{"highest plan", []string{"plan-basic", "plan-pro"}, 5},
		{"vpn admin with plan", []string{"vpn-admins", "plan-pro"}, 7},
		{"similar group", []string{"vpn-admins-extra"}, 1},
		{"different case", []string{"VPN-ADMINS"}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := cfg.WSMaxForGroups(test.groups); got != test.want {
				t.Fatalf("WSMaxForGroups(%v) = %d, want %d", test.groups, got, test.want)
			}
		})
	}
}
