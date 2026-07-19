package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const MaxOriginIDLength = 128

// CollectionOrigin identifies the one collector host and private-network
// realm whose observations may share a server database. It is admission
// provenance, not cryptographic authentication.
type CollectionOrigin struct {
	HostID         string `json:"host_id"`
	NetworkRealmID string `json:"network_realm_id"`
}

func (o CollectionOrigin) Validate() error {
	if err := ValidateOriginID("host_id", o.HostID); err != nil {
		return err
	}
	if err := ValidateOriginID("network_realm_id", o.NetworkRealmID); err != nil {
		return err
	}
	return nil
}

// ValidateOriginID requires an already-canonical, nonsecret identifier. No
// trimming or case normalization is performed because the same bytes are the
// database admission boundary.
func ValidateOriginID(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > MaxOriginIDLength {
		return fmt.Errorf("%s must be at most %d bytes", field, MaxOriginIDLength)
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		valid := char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
		if index > 0 {
			valid = valid || char == '.' || char == '_' || char == '-'
		}
		if !valid {
			return fmt.Errorf(
				"%s must match [a-z0-9][a-z0-9._-]{0,%d}",
				field,
				MaxOriginIDLength-1,
			)
		}
	}
	return nil
}

// OriginDigest is a stable comparison value for storage binding records.
func OriginDigest(origin CollectionOrigin) string {
	sum := sha256.Sum256([]byte(
		"agenthound-origin-v1\x00" + origin.HostID + "\x00" + origin.NetworkRealmID,
	))
	return hex.EncodeToString(sum[:])
}
