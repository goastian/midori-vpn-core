package control

import (
	"cmp"
	"slices"
	"strings"

	"github.com/goastian/midori-vpn-core/internal/nodeauth"
)

func paginateNodeIdentities(identities []nodeauth.RegisteredIdentity, query pageQuery) ([]nodeauth.RegisteredIdentity, int) {
	search := strings.ToLower(query.Search)
	filtered := make([]nodeauth.RegisteredIdentity, 0, len(identities))
	for _, identity := range identities {
		if search != "" && !strings.HasPrefix(strings.ToLower(identity.NodeID), search) {
			continue
		}
		if query.Status == "active" && identity.Revoked {
			continue
		}
		if query.Status == "revoked" && !identity.Revoked {
			continue
		}
		filtered = append(filtered, identity)
	}
	slices.SortFunc(filtered, func(left, right nodeauth.RegisteredIdentity) int {
		comparison := cmp.Compare(strings.ToLower(left.NodeID), strings.ToLower(right.NodeID))
		if query.Sort == "source" {
			comparison = cmp.Compare(strings.ToLower(left.Source), strings.ToLower(right.Source))
			if comparison == 0 {
				comparison = cmp.Compare(strings.ToLower(left.NodeID), strings.ToLower(right.NodeID))
			}
		}
		if query.Order == "desc" {
			return -comparison
		}
		return comparison
	})

	total := len(filtered)
	start := min(query.Offset(), total)
	end := min(start+query.PageSize, total)
	return filtered[start:end], total
}
