package processors

import "fmt"

// compatibleScopePredicate is the one compatibility rule used by processors
// that compare otherwise unrelated observations:
//   - artifact-local evidence composes only within the same weak artifact;
//   - two network observations require the same network context;
//   - collection-point evidence composes with that point's current or retained
//     network observations, but never with another collection point.
func compatibleScopePredicate(left, right string) string {
	return fmt.Sprintf(`(
    (%[1]s.identity_scope = 'artifact'
      AND %[2]s.identity_scope = 'artifact'
      AND %[1]s.identity_scope_id = %[2]s.identity_scope_id)
    OR
    (%[1]s.identity_scope IN ['collection_point', 'network_context']
      AND %[2]s.identity_scope IN ['collection_point', 'network_context']
      AND %[1]s.collection_point_id IS NOT NULL
      AND %[1]s.collection_point_id = %[2]s.collection_point_id
      AND (
        %[1]s.identity_scope = 'collection_point'
        OR %[2]s.identity_scope = 'collection_point'
        OR %[1]s.network_context_id = %[2]s.network_context_id
      ))
  )`, left, right)
}

type scopeCoordinates struct {
	kind             string
	id               string
	collectionPoint  string
	networkContextID string
}

func scopesCompatible(left, right scopeCoordinates) bool {
	if left.kind == "artifact" || right.kind == "artifact" {
		return left.kind == "artifact" && right.kind == "artifact" &&
			left.id != "" && left.id == right.id
	}
	if left.collectionPoint == "" || left.collectionPoint != right.collectionPoint {
		return false
	}
	if left.kind == "collection_point" || right.kind == "collection_point" {
		leftKnown := left.kind == "collection_point" || left.kind == "network_context"
		rightKnown := right.kind == "collection_point" || right.kind == "network_context"
		return leftKnown && rightKnown
	}
	return left.kind == "network_context" && right.kind == "network_context" &&
		left.networkContextID != "" && left.networkContextID == right.networkContextID
}
