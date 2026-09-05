package action

import "testing"

func TestCanonicalEndpointIdentityUsesEffectivePortSemantics(t *testing.T) {
	tests := []struct {
		name   string
		left   Target
		right  Target
		equal  bool
		result string
	}{
		{
			name: "bare Qdrant host uses service port", left: Target{Address: "QDRANT"},
			right: Target{Address: "qdrant:6333"}, equal: true, result: "http://qdrant:6333",
		},
		{
			name: "implicit HTTP equals port 80", left: Target{Address: "http://QDRANT/"},
			right: Target{Address: "http://qdrant:80"}, equal: true, result: "http://qdrant",
		},
		{
			name: "implicit HTTPS equals port 443", left: Target{Address: "https://QDRANT/base/"},
			right: Target{Address: "https://qdrant:443/base"}, equal: true, result: "https://qdrant/base",
		},
		{
			name: "HTTP port 80 differs from Qdrant port", left: Target{Address: "http://qdrant"},
			right: Target{Address: "http://qdrant:6333"}, equal: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, err := CanonicalEndpointIdentity(test.left, 6333, "http")
			if err != nil {
				t.Fatalf("left identity: %v", err)
			}
			right, err := CanonicalEndpointIdentity(test.right, 6333, "http")
			if err != nil {
				t.Fatalf("right identity: %v", err)
			}
			if (left == right) != test.equal {
				t.Fatalf("identities %q and %q equality = %t, want %t", left, right, left == right, test.equal)
			}
			if test.result != "" && left != test.result {
				t.Fatalf("canonical identity = %q, want %q", left, test.result)
			}
		})
	}
}

func TestCanonicalEndpointIdentityStripsUnsafeURLComponents(t *testing.T) {
	got, err := CanonicalEndpointIdentity(Target{
		Address: "https://user:secret@QDRANT:443/base/?token=secret#fragment",
	}, 6333, "http")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://qdrant/base" {
		t.Fatalf("canonical identity = %q, want sanitized base URL", got)
	}
}
