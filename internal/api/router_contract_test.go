package api

import (
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/clientpki"
	"github.com/goastian/midori-vpn-core/internal/config"
)

var contractHTTPMethods = map[string]struct{}{
	http.MethodDelete:  {},
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodOptions: {},
	http.MethodPatch:   {},
	http.MethodPost:    {},
	http.MethodPut:     {},
	http.MethodTrace:   {},
}

type openAPIContract struct {
	OpenAPI string                    `yaml:"openapi"`
	Paths   map[string]map[string]any `yaml:"paths"`
}

func TestRouterMatchesOpenAPIContract(t *testing.T) {
	specData, err := os.ReadFile("../../docs/openapi.yaml")
	require.NoError(t, err)

	var spec openAPIContract
	require.NoError(t, yaml.Unmarshal(specData, &spec))
	require.Equal(t, "3.1.0", spec.OpenAPI)

	specOperations := make(map[string]string)
	operationIDs := make(map[string]string)
	for path, pathItem := range spec.Paths {
		for method, rawOperation := range pathItem {
			upperMethod := strings.ToUpper(method)
			if _, ok := contractHTTPMethods[upperMethod]; !ok {
				continue
			}

			operation, ok := rawOperation.(map[string]any)
			require.Truef(t, ok, "%s %s is not an OpenAPI operation", upperMethod, path)
			operationID, ok := operation["operationId"].(string)
			require.Truef(t, ok && operationID != "", "%s %s has no operationId", upperMethod, path)

			key := upperMethod + " " + path
			require.Emptyf(t, specOperations[key], "duplicate OpenAPI operation %s", key)
			require.Emptyf(t, operationIDs[operationID], "operationId %q is shared by %s and %s", operationID, operationIDs[operationID], key)
			specOperations[key] = operationID
			operationIDs[operationID] = key
		}
	}

	cfg := &config.Config{
		ExtensionCallbackPath:   "/extension/callback",
		CredentialSigningSecret: strings.Repeat("c", 32),
		WGPort:                  51820,
		WSSTunnelEnabled:        true,
		WSSTunnelServerID:       "00000000-0000-0000-0000-000000000001",
		WSSTunnelMaxClients:     1,
	}
	router := newRouter(
		cfg,
		nil,
		&pgxpool.Pool{},
		&auth.JWKSProvider{},
		nil,
		&clientpki.Authority{},
		nil,
		false,
	)

	routerOperations := make(map[string]struct{})
	err = chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if _, ok := contractHTTPMethods[method]; ok {
			routerOperations[method+" "+route] = struct{}{}
		}
		return nil
	})
	require.NoError(t, err)

	require.Empty(t, operationDifference(routerOperations, specOperations), "router operations missing from OpenAPI")
	require.Empty(t, operationDifference(specOperations, routerOperations), "OpenAPI operations missing from router")
	require.NotEmpty(t, routerOperations)
}

func operationDifference[T, U any](left map[string]T, right map[string]U) []string {
	difference := make([]string, 0)
	for operation := range left {
		if _, ok := right[operation]; !ok {
			difference = append(difference, operation)
		}
	}
	sort.Strings(difference)
	return difference
}
