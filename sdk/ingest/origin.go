package ingest

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"sort"
	"strings"
)

const (
	CollectionIdentityScheme  = "agenthound_collection_v1"
	CollectionIdentityVersion = 1

	IdentityQualityStrong IdentityQuality = "strong"
	IdentityQualityWeak   IdentityQuality = "weak"

	NetworkClassOffline NetworkClass = "offline"
	NetworkClassPrivate NetworkClass = "private"
	NetworkClassPublic  NetworkClass = "public"
	NetworkClassMixed   NetworkClass = "mixed"
)

type IdentityQuality string
type NetworkClass string

// IdentityEvidence contains only an application-specific HMAC of a native
// platform signal. Raw machine, account, container, route, DNS, and adapter
// identifiers never enter the artifact.
type IdentityEvidence struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

// CollectionIdentity identifies the execution vantage and its observable
// network view. It is deterministic collection provenance, not host
// authentication or attestation.
type CollectionIdentity struct {
	Scheme            string             `json:"scheme"`
	Version           int                `json:"version"`
	CollectionPointID string             `json:"collection_point_id"`
	NetworkContextID  string             `json:"network_context_id"`
	Quality           IdentityQuality    `json:"quality"`
	NetworkClass      NetworkClass       `json:"network_class"`
	Evidence          []IdentityEvidence `json:"evidence"`
	NetworkEvidence   []IdentityEvidence `json:"network_evidence"`
}

// NewCollectionIdentity creates the versioned record from already-HMACed
// signals. The server repeats this derivation to validate internal consistency.
func NewCollectionIdentity(
	evidence, networkEvidence []IdentityEvidence,
	networkClass NetworkClass,
) CollectionIdentity {
	evidence = canonicalEvidence(evidence)
	networkEvidence = canonicalEvidence(networkEvidence)
	quality := IdentityQualityWeak
	if hasEvidenceKind(evidence, "os_instance") && hasEvidenceKind(evidence, "principal") {
		quality = IdentityQualityStrong
	}
	pointID := evidenceID("agenthound-collection-point-v1", evidence)
	networkID := framedSHA256(
		"agenthound-network-context-v1",
		pointID,
		evidenceID("agenthound-network-evidence-v1", networkEvidence),
	)
	return CollectionIdentity{
		Scheme:            CollectionIdentityScheme,
		Version:           CollectionIdentityVersion,
		CollectionPointID: pointID,
		NetworkContextID:  networkID,
		Quality:           quality,
		NetworkClass:      networkClass,
		Evidence:          evidence,
		NetworkEvidence:   networkEvidence,
	}
}

func (i CollectionIdentity) Validate() error {
	if i.Scheme != CollectionIdentityScheme {
		return fmt.Errorf("scheme must be %q", CollectionIdentityScheme)
	}
	if i.Version != CollectionIdentityVersion {
		return fmt.Errorf("version must be %d", CollectionIdentityVersion)
	}
	if len(i.Evidence) == 0 {
		return fmt.Errorf("evidence must not be empty")
	}
	if len(i.NetworkEvidence) == 0 {
		return fmt.Errorf("network_evidence must not be empty")
	}
	for name, values := range map[string][]IdentityEvidence{
		"evidence": i.Evidence, "network_evidence": i.NetworkEvidence,
	} {
		if err := validateEvidence(name, values); err != nil {
			return err
		}
	}
	if err := validateEvidenceKinds(i.Evidence, i.NetworkEvidence); err != nil {
		return err
	}
	if expectedClass := classifyNetworkEvidence(i.NetworkEvidence); i.NetworkClass != expectedClass {
		return fmt.Errorf("network_class is inconsistent with network_evidence")
	}
	expected := NewCollectionIdentity(i.Evidence, i.NetworkEvidence, i.NetworkClass)
	if i.CollectionPointID != expected.CollectionPointID {
		return fmt.Errorf("collection_point_id is inconsistent with evidence")
	}
	if i.NetworkContextID != expected.NetworkContextID {
		return fmt.Errorf("network_context_id is inconsistent with evidence")
	}
	if i.Quality != expected.Quality {
		return fmt.Errorf("quality is inconsistent with evidence")
	}
	if !validNetworkClass(i.NetworkClass) {
		return fmt.Errorf("network_class is invalid")
	}
	if i.NetworkClass == NetworkClassOffline &&
		(len(i.NetworkEvidence) != 1 || i.NetworkEvidence[0].Kind != "offline") {
		return fmt.Errorf("offline network_class requires only offline evidence")
	}
	return nil
}

func validateEvidence(field string, values []IdentityEvidence) error {
	canonical := canonicalEvidence(values)
	if len(canonical) != len(values) {
		return fmt.Errorf("%s contains duplicate evidence", field)
	}
	for index, value := range values {
		if value.Kind == "" || strings.TrimSpace(value.Kind) != value.Kind {
			return fmt.Errorf("%s[%d].kind is invalid", field, index)
		}
		for _, char := range value.Kind {
			if (char < 'a' || char > 'z') && char != '_' {
				return fmt.Errorf("%s[%d].kind is invalid", field, index)
			}
		}
		if !isCanonicalHMACSHA256(value.Digest) {
			return fmt.Errorf("%s[%d].digest must be a canonical hmac-sha256", field, index)
		}
		if value != canonical[index] {
			return fmt.Errorf("%s must be sorted by kind and digest", field)
		}
	}
	return nil
}

func validateEvidenceKinds(identity, network []IdentityEvidence) error {
	identityKinds := map[string]bool{
		"artifact": true, "container": true, "filesystem": true,
		"hostname": true, "mac": true, "os_instance": true,
		"platform": true, "principal": true,
	}
	networkKinds := map[string]bool{
		"default_gateway": true, "dns_domain": true, "network_profile": true,
		"offline": true, "route_private": true, "route_public": true,
	}
	for index, value := range identity {
		if !identityKinds[value.Kind] {
			return fmt.Errorf("evidence[%d].kind is not supported by identity scheme version %d", index, CollectionIdentityVersion)
		}
	}
	for index, value := range network {
		if !networkKinds[value.Kind] {
			return fmt.Errorf("network_evidence[%d].kind is not supported by identity scheme version %d", index, CollectionIdentityVersion)
		}
	}
	return nil
}

func classifyNetworkEvidence(values []IdentityEvidence) NetworkClass {
	var private, public bool
	for _, value := range values {
		switch value.Kind {
		case "default_gateway", "dns_domain", "network_profile", "route_private":
			private = true
		case "route_public":
			public = true
		}
	}
	switch {
	case private && public:
		return NetworkClassMixed
	case private:
		return NetworkClassPrivate
	case public:
		return NetworkClassPublic
	default:
		return NetworkClassOffline
	}
}

func canonicalEvidence(values []IdentityEvidence) []IdentityEvidence {
	seen := make(map[string]bool, len(values))
	out := make([]IdentityEvidence, 0, len(values))
	for _, value := range values {
		key := value.Kind + "\x00" + value.Digest
		if value.Kind == "" || value.Digest == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Kind == out[b].Kind {
			return out[a].Digest < out[b].Digest
		}
		return out[a].Kind < out[b].Kind
	})
	return out
}

func hasEvidenceKind(values []IdentityEvidence, kind string) bool {
	for _, value := range values {
		if value.Kind == kind {
			return true
		}
	}
	return false
}

func evidenceID(domain string, values []IdentityEvidence) string {
	h := sha256.New()
	writeIdentityFrame(h, domain)
	for _, value := range canonicalEvidence(values) {
		writeIdentityFrame(h, value.Kind)
		writeIdentityFrame(h, value.Digest)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

func framedSHA256(values ...string) string {
	h := sha256.New()
	for _, value := range values {
		writeIdentityFrame(h, value)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

func writeIdentityFrame(h hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}

func isCanonicalHMACSHA256(value string) bool {
	const prefix = "hmac-sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, char := range value[len(prefix):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func validNetworkClass(value NetworkClass) bool {
	switch value {
	case NetworkClassOffline, NetworkClassPrivate, NetworkClassPublic, NetworkClassMixed:
		return true
	default:
		return false
	}
}
