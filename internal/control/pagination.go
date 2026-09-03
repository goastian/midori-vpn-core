package control

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

const (
	defaultPageSize = 20
	maximumPageSize = 100
	maximumListText = 128
)

type pageQueryConfig struct {
	DefaultSort string
	Sorts       []string
	Statuses    []string
	AllowSearch bool
	Extras      []string
}

type pageQuery struct {
	Page     int
	PageSize int
	Search   string
	Status   string
	Sort     string
	Order    string
	Extras   map[string]string
}

func (q pageQuery) Offset() int {
	return (q.Page - 1) * q.PageSize
}

type pageResponse[T any] struct {
	Items    []T `json:"items"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

func newPageResponse[T any](items []T, query pageQuery, total int) pageResponse[T] {
	if items == nil {
		items = make([]T, 0)
	}
	return pageResponse[T]{Items: items, Page: query.Page, PageSize: query.PageSize, Total: total}
}

func requirePageQuery(w http.ResponseWriter, r *http.Request, config pageQueryConfig) (pageQuery, bool) {
	query, err := parsePageQuery(r, config)
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return pageQuery{}, false
	}
	return query, true
}

func (q pageQuery) ListOptions() repo.ListOptions {
	return repo.ListOptions{
		Limit: q.PageSize, Offset: q.Offset(), Search: q.Search,
		Status: q.Status, Sort: q.Sort, Order: q.Order,
	}
}

func parsePageQuery(r *http.Request, config pageQueryConfig) (pageQuery, error) {
	query := pageQuery{
		Page:     1,
		PageSize: defaultPageSize,
		Status:   "all",
		Sort:     config.DefaultSort,
		Order:    "desc",
		Extras:   make(map[string]string, len(config.Extras)),
	}

	allowed := map[string]bool{
		"page": true, "page_size": true, "status": true, "sort": true, "order": true,
	}
	if config.AllowSearch {
		allowed["search"] = true
	}
	for _, extra := range config.Extras {
		allowed[extra] = true
	}
	for key, values := range r.URL.Query() {
		if !allowed[key] {
			return pageQuery{}, fmt.Errorf("unsupported query parameter %q", key)
		}
		if len(values) != 1 {
			return pageQuery{}, fmt.Errorf("query parameter %q must be provided once", key)
		}
	}

	var err error
	if raw, ok := singleQueryValue(r, "page"); ok {
		query.Page, err = strconv.Atoi(raw)
		if err != nil || query.Page < 1 {
			return pageQuery{}, fmt.Errorf("page must be a positive integer")
		}
	}
	if raw, ok := singleQueryValue(r, "page_size"); ok {
		query.PageSize, err = strconv.Atoi(raw)
		if err != nil || query.PageSize < 1 || query.PageSize > maximumPageSize {
			return pageQuery{}, fmt.Errorf("page_size must be between 1 and %d", maximumPageSize)
		}
	}
	if query.Page-1 > math.MaxInt/query.PageSize {
		return pageQuery{}, fmt.Errorf("page is too large")
	}

	if config.AllowSearch {
		query.Search = strings.TrimSpace(r.URL.Query().Get("search"))
		if err := validateListText("search", query.Search); err != nil {
			return pageQuery{}, err
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("status")); raw != "" {
		query.Status = raw
	}
	if !containsString(config.Statuses, query.Status) {
		return pageQuery{}, fmt.Errorf("unsupported status %q", query.Status)
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("sort")); raw != "" {
		query.Sort = raw
	}
	if !containsString(config.Sorts, query.Sort) {
		return pageQuery{}, fmt.Errorf("unsupported sort %q", query.Sort)
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("order")); raw != "" {
		query.Order = raw
	}
	if query.Order != "asc" && query.Order != "desc" {
		return pageQuery{}, fmt.Errorf("order must be asc or desc")
	}
	for _, extra := range config.Extras {
		value := strings.TrimSpace(r.URL.Query().Get(extra))
		if err := validateListText(extra, value); err != nil {
			return pageQuery{}, err
		}
		query.Extras[extra] = value
	}
	return query, nil
}

func singleQueryValue(r *http.Request, key string) (string, bool) {
	values, ok := r.URL.Query()[key]
	if !ok {
		return "", false
	}
	return values[0], true
}

func validateListText(name, value string) error {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximumListText {
		return fmt.Errorf("%s must contain at most %d characters", name, maximumListText)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s contains control characters", name)
	}
	return nil
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
