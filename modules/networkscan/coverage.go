package networkscan

import (
	"sort"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

const logicalTargetSetVersion = 1

// TargetSetIdentity describes the exact logical hosts expanded for scheduling
// without retaining those hosts in artifact metadata.
type TargetSetIdentity struct {
	Count  int    `json:"count"`
	Digest string `json:"digest"`
}

// LogicalTargetSetIdentity canonicalizes the expanded logical host set. It is
// intentionally DNS-free: hostname literals remain hostname literals.
func LogicalTargetSetIdentity(hosts []string) TargetSetIdentity {
	canonical := append([]string(nil), hosts...)
	sort.Strings(canonical)
	canonical = compactSortedStrings(canonical)
	digest, err := common.CanonicalJSONHash(struct {
		Version int      `json:"version"`
		Targets []string `json:"targets"`
	}{
		Version: logicalTargetSetVersion,
		Targets: canonical,
	})
	if err != nil {
		panic("hash logical target strings: " + err.Error())
	}
	return TargetSetIdentity{
		Count:  len(canonical),
		Digest: "sha256:" + digest,
	}
}

func compactSortedStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] == values[write-1] {
			continue
		}
		values[write] = values[read]
		write++
	}
	return values[:write]
}
