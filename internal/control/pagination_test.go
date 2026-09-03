package control

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/nodeauth"
)

func TestParsePageQueryDefaults(t *testing.T) {
	r := httptest.NewRequest("GET", "/admin/resources", nil)
	query, err := parsePageQuery(r, pageQueryConfig{
		DefaultSort: "created_at",
		Sorts:       []string{"created_at"},
		Statuses:    []string{"all"},
	})
	if err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	if query.Page != 1 || query.PageSize != 20 || query.Status != "all" || query.Sort != "created_at" || query.Order != "desc" {
		t.Fatalf("unexpected defaults: %+v", query)
	}
}

func TestParsePageQueryAcceptsAllowlistedValues(t *testing.T) {
	r := httptest.NewRequest("GET", "/admin/resources?page=3&page_size=10&search=%20Alpha%20&status=active&sort=name&order=asc&action=login", nil)
	query, err := parsePageQuery(r, pageQueryConfig{
		DefaultSort: "created_at",
		Sorts:       []string{"created_at", "name"},
		Statuses:    []string{"all", "active"},
		AllowSearch: true,
		Extras:      []string{"action"},
	})
	if err != nil {
		t.Fatalf("parse allowlisted query: %v", err)
	}
	if query.Page != 3 || query.PageSize != 10 || query.Offset() != 20 || query.Search != "Alpha" || query.Status != "active" || query.Sort != "name" || query.Order != "asc" || query.Extras["action"] != "login" {
		t.Fatalf("unexpected query: %+v", query)
	}
}

func TestParsePageQueryRejectsInvalidValues(t *testing.T) {
	config := pageQueryConfig{
		DefaultSort: "created_at",
		Sorts:       []string{"created_at"},
		Statuses:    []string{"all", "active"},
		AllowSearch: true,
		Extras:      []string{"action"},
	}
	cases := map[string]string{
		"unknown":          "unknown=value",
		"duplicate":        "page=1&page=2",
		"zero page":        "page=0",
		"non-numeric page": "page=no",
		"oversized page":   "page=9223372036854775807&page_size=100",
		"zero size":        "page_size=0",
		"large size":       "page_size=101",
		"status":           "status=missing",
		"sort":             "sort=missing",
		"order":            "order=random",
		"control search":   "search=hello%0Aworld",
		"long action":      "action=" + strings.Repeat("a", maximumListText+1),
	}
	for name, rawQuery := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/admin/resources?"+rawQuery, nil)
			if _, err := parsePageQuery(r, config); err == nil {
				t.Fatalf("expected %q to fail", rawQuery)
			}
		})
	}
}

func TestPaginateNodeIdentitiesFiltersSortsAndPages(t *testing.T) {
	identities := []nodeauth.RegisteredIdentity{
		{NodeID: "charlie", Source: "redis", Revoked: false},
		{NodeID: "Alpha", Source: "config", Revoked: false},
		{NodeID: "alpine", Source: "config", Revoked: true},
		{NodeID: "bravo", Source: "redis", Revoked: false},
	}

	items, total := paginateNodeIdentities(identities, pageQuery{
		Page: 1, PageSize: 1, Search: "al", Status: "all", Sort: "node_id", Order: "asc",
	})
	if total != 2 || len(items) != 1 || items[0].NodeID != "Alpha" {
		t.Fatalf("unexpected filtered page: total=%d items=%+v", total, items)
	}

	items, total = paginateNodeIdentities(identities, pageQuery{
		Page: 1, PageSize: 10, Status: "revoked", Sort: "source", Order: "desc",
	})
	if total != 1 || len(items) != 1 || items[0].NodeID != "alpine" {
		t.Fatalf("unexpected revoked page: total=%d items=%+v", total, items)
	}
}

func TestNewPageResponseUsesEmptyItems(t *testing.T) {
	response := newPageResponse[string](nil, pageQuery{Page: 2, PageSize: 10}, 0)
	if response.Items == nil || len(response.Items) != 0 || response.Page != 2 || response.PageSize != 10 || response.Total != 0 {
		t.Fatalf("unexpected response: %+v", response)
	}
}
