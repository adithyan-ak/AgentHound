package appdb

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

type coverageHead struct {
	Key              string
	ScanID           string
	Root             string
	State            sdkingest.OutcomeState
	Mode             sdkingest.InstructionCoverageMode
	RegistryContract *sdkingest.RegistryContract
	UpdatedAt        time.Time
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

func retiredCoverageKeys(
	roots []sdkingest.CoverageRoot,
	heads []coverageHead,
	inheritedDirty []string,
	dirtyParents map[string]string,
) []string {
	activeByRoot := make(map[string]map[string]bool, len(roots))
	for _, root := range roots {
		active := make(map[string]bool, len(root.ChildCoverageKeys))
		for _, child := range root.ChildCoverageKeys {
			if child = strings.TrimSpace(child); child != "" {
				active[child] = true
			}
		}
		activeByRoot[root.CoverageKey] = active
	}
	candidates := append([]coverageHead(nil), heads...)
	for _, key := range inheritedDirty {
		if root := dirtyParents[key]; root != "" {
			candidates = append(candidates, coverageHead{Key: key, Root: root})
		}
	}

	var retired []string
	for _, candidate := range candidates {
		active, authoritative := activeByRoot[candidate.Root]
		if authoritative && !active[candidate.Key] {
			retired = append(retired, candidate.Key)
		}
	}
	return normalizeCoverageKeys(retired)
}

func comparisonKeyWithCoverageHeads(
	base string,
	currentCoverage []string,
	heads []coverageHead,
) string {
	if strings.TrimSpace(base) == "" {
		return ""
	}
	currentContract := sdkingest.CurrentInstructionRegistryContract()
	for _, head := range heads {
		if head.Mode == "" {
			continue
		}
		if head.State != sdkingest.OutcomeComplete ||
			head.RegistryContract == nil ||
			!head.RegistryContract.Equal(currentContract) {
			return ""
		}
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
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(head.Key))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(head.Root))
		if head.Mode != "" {
			_, _ = hash.Write([]byte{0})
			_, _ = hash.Write([]byte(head.Mode))
			_, _ = hash.Write([]byte{0})
			_, _ = hash.Write([]byte(head.State))
			_, _ = hash.Write([]byte{0})
			_, _ = hash.Write([]byte(head.RegistryContract.Digest))
			_, _ = hash.Write([]byte{0})
			_, _ = hash.Write([]byte{
				byte(head.RegistryContract.Generation >> 24),
				byte(head.RegistryContract.Generation >> 16),
				byte(head.RegistryContract.Generation >> 8),
				byte(head.RegistryContract.Generation),
			})
		}
		if !current[head.Key] {
			_, _ = hash.Write([]byte{0})
			_, _ = hash.Write([]byte(head.ScanID))
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func activePostureCoverageRoots(heads []coverageHead) []model.PostureCoverageRoot {
	roots := make([]model.PostureCoverageRoot, 0)
	currentContract := sdkingest.CurrentInstructionRegistryContract()
	for _, head := range heads {
		if head.Mode == "" || head.RegistryContract == nil {
			continue
		}
		roots = append(roots, model.PostureCoverageRoot{
			CoverageKey:      head.Key,
			Mode:             head.Mode,
			State:            head.State,
			ScanID:           head.ScanID,
			ObservedAt:       head.UpdatedAt,
			RegistryContract: *head.RegistryContract,
			ContractCurrent:  head.RegistryContract.Equal(currentContract),
		})
	}
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].Mode == roots[j].Mode {
			return roots[i].CoverageKey < roots[j].CoverageKey
		}
		return roots[i].Mode < roots[j].Mode
	})
	return roots
}

func postureCoverageRootsLimited(roots []model.PostureCoverageRoot) bool {
	for _, root := range roots {
		if root.State != sdkingest.OutcomeComplete || !root.ContractCurrent {
			return true
		}
	}
	return false
}
