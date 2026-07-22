package processors

import (
	"context"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestScopesCompatibleMatrix(t *testing.T) {
	pointA := scopeCoordinates{kind: "collection_point", id: "point-a", collectionPoint: "point-a"}
	pointB := scopeCoordinates{kind: "collection_point", id: "point-b", collectionPoint: "point-b"}
	networkA1 := scopeCoordinates{kind: "network_context", id: "network-a1", collectionPoint: "point-a", networkContextID: "network-a1"}
	networkA2 := scopeCoordinates{kind: "network_context", id: "network-a2", collectionPoint: "point-a", networkContextID: "network-a2"}
	networkB1 := scopeCoordinates{kind: "network_context", id: "network-b1", collectionPoint: "point-b", networkContextID: "network-b1"}
	artifactA := scopeCoordinates{kind: "artifact", id: "artifact-a"}
	artifactB := scopeCoordinates{kind: "artifact", id: "artifact-b"}

	for _, test := range []struct {
		name        string
		left, right scopeCoordinates
		want        bool
	}{
		{name: "same point", left: pointA, right: pointA, want: true},
		{name: "point and its network", left: pointA, right: networkA1, want: true},
		{name: "same network", left: networkA1, right: networkA1, want: true},
		{name: "different networks at same point", left: networkA1, right: networkA2, want: false},
		{name: "different points", left: pointA, right: pointB, want: false},
		{name: "different point networks", left: networkA1, right: networkB1, want: false},
		{name: "same weak artifact", left: artifactA, right: artifactA, want: true},
		{name: "different weak artifacts", left: artifactA, right: artifactB, want: false},
		{name: "weak and strong", left: artifactA, right: pointA, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := scopesCompatible(test.left, test.right); got != test.want {
				t.Fatalf("scopesCompatible() = %v, want %v", got, test.want)
			}
			if got := scopesCompatible(test.right, test.left); got != test.want {
				t.Fatalf("reverse scopesCompatible() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCrossVantageProcessorsUseExactCompatibilityPredicate(t *testing.T) {
	for name, processor := range map[string]evidenceProcessor{
		"can_reach":       &CanReach{},
		"can_exfiltrate":  &CanExfiltrate{},
		"confused_deputy": &ConfusedDeputy{},
		"shadows":         &Shadows{},
		"taints":          &Taints{},
	} {
		t.Run(name, func(t *testing.T) {
			db := &graph.MockGraphDB{}
			if _, err := processor.Process(context.Background(), db, "scope-policy"); err != nil {
				t.Fatal(err)
			}
			var guarded bool
			for _, call := range db.CallsTo("ExecuteWrite") {
				cypher, _ := call.Args[0].(string)
				if strings.Contains(cypher, "collection_point_id") &&
					strings.Contains(cypher, "network_context_id") &&
					strings.Contains(cypher, "identity_scope = 'artifact'") {
					guarded = true
				}
			}
			if !guarded {
				t.Fatalf("processor has no exact vantage-compatibility predicate")
			}
		})
	}
}

func TestCredentialValueHashCorrelationRemainsExplicitlyGlobal(t *testing.T) {
	db := &graph.MockGraphDB{}
	if _, err := (&CrossServiceCredentialChain{}).Process(context.Background(), db, "scope-policy"); err != nil {
		t.Fatal(err)
	}
	calls := db.CallsTo("ExecuteWrite")
	if len(calls) != 1 {
		t.Fatalf("writes = %d, want 1", len(calls))
	}
	cypher, _ := calls[0].Args[0].(string)
	if !strings.Contains(cypher, "c1master.value_hash = c1.value_hash") {
		t.Fatal("credential processor lost its approved global value_hash join")
	}
	if strings.Contains(cypher, "collection_point_id") || strings.Contains(cypher, "network_context_id") {
		t.Fatal("approved global credential correlation was accidentally vantage-scoped")
	}
}
