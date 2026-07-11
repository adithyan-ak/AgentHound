package appdb

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

type coverageHead struct {
	Key    string
	ScanID string
}

func normalizeCoverageKeys(groups ...[]string) []string {
	seen := make(map[string]bool)
	var keys []string
	for _, group := range groups {
		for _, key := range group {
			key = strings.TrimSpace(key)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func subtractCoverageKeys(keys []string, replaced ...[]string) []string {
	remove := make(map[string]bool)
	for _, group := range replaced {
		for _, key := range group {
			if key = strings.TrimSpace(key); key != "" {
				remove[key] = true
			}
		}
	}
	var remaining []string
	for _, key := range normalizeCoverageKeys(keys) {
		if !remove[key] {
			remaining = append(remaining, key)
		}
	}
	return remaining
}

func finalizedDirtyCoverage(
	inherited []string,
	complete []string,
	resolved []string,
	explicitlyDirty []string,
) []string {
	remaining := subtractCoverageKeys(inherited, complete, resolved)
	return normalizeCoverageKeys(remaining, explicitlyDirty)
}

func comparisonKeyWithCoverageHeads(
	base string,
	currentCoverage []string,
	heads []coverageHead,
) string {
	if strings.TrimSpace(base) == "" {
		return ""
	}
	current := make(map[string]bool, len(currentCoverage))
	for _, key := range normalizeCoverageKeys(currentCoverage) {
		current[key] = true
	}
	sortedHeads := append([]coverageHead(nil), heads...)
	sort.Slice(sortedHeads, func(i, j int) bool {
		if sortedHeads[i].Key == sortedHeads[j].Key {
			return sortedHeads[i].ScanID < sortedHeads[j].ScanID
		}
		return sortedHeads[i].Key < sortedHeads[j].Key
	})
	hash := sha256.New()
	_, _ = hash.Write([]byte(base))
	for _, head := range sortedHeads {
		if current[head.Key] {
			continue
		}
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(head.Key))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(head.ScanID))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
