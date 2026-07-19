package action

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const receiptIDBytes = 18

// NewReceiptID returns a random opaque receipt reference. It is deliberately
// independent of target paths, receipt contents, and mutation state.
func NewReceiptID() (string, error) {
	var entropy [receiptIDBytes]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generate receipt id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(entropy[:]), nil
}
