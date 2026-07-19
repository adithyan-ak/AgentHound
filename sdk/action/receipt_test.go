package action

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewReceiptIDIsOpaqueAndUnique(t *testing.T) {
	const sensitive = "/Users/operator/.cursor/mcp.json|injected-token"
	seen := make(map[string]bool)
	for range 128 {
		receiptID, err := NewReceiptID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[receiptID] {
			t.Fatalf("duplicate receipt id %q", receiptID)
		}
		seen[receiptID] = true
		decoded, err := base64.RawURLEncoding.DecodeString(receiptID)
		if err != nil || len(decoded) != receiptIDBytes {
			t.Fatalf("receipt id %q is not opaque random encoding", receiptID)
		}
		if strings.Contains(sensitive, receiptID) || strings.Contains(receiptID, sensitive) {
			t.Fatalf("receipt id contains target or content material: %q", receiptID)
		}
	}
}
