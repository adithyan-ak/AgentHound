package cli

import (
	"sort"

	"github.com/adithyan-ak/agenthound/modules/networkscan"
	"github.com/adithyan-ak/agenthound/modules/protoscan"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const probeContractVersion = 1

type probeFingerprinter struct {
	ModuleID string `json:"module_id"`
	Target   string `json:"target"`
	Version  string `json:"version"`
}

type probeSemantic struct {
	Type           string `json:"type"`
	ID             string `json:"id"`
	Version        int    `json:"version"`
	SemanticSHA256 string `json:"semantic_sha256"`
}

type networkProbeContract struct {
	Version        int                           `json:"version"`
	Scanner        string                        `json:"scanner"`
	Targets        networkscan.TargetSetIdentity `json:"targets"`
	Ports          []int                         `json:"ports"`
	Fingerprinters []probeFingerprinter          `json:"fingerprinters"`
	Semantics      []probeSemantic               `json:"semantics"`
}

type protocolProbeContract struct {
	Version   int                           `json:"version"`
	Scanner   string                        `json:"scanner"`
	Targets   networkscan.TargetSetIdentity `json:"targets"`
	Protocols []protoscan.ProtocolSurface   `json:"protocols"`
}

type probeContractIdentity struct {
	CoverageKey string
	Digest      string
}

func buildNetworkProbeContract(
	report networkscan.ProbeReport,
	candidates []fingerprintCandidate,
	ruleset *ingest.RulesetManifest,
) networkProbeContract {
	fingerprinters := make([]probeFingerprinter, 0, len(candidates))
	targets := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		fingerprinters = append(fingerprinters, probeFingerprinter{
			ModuleID: candidate.id,
			Target:   candidate.target,
			Version:  candidate.version,
		})
		targets[candidate.target] = true
	}
	sort.Slice(fingerprinters, func(i, j int) bool {
		if fingerprinters[i].ModuleID != fingerprinters[j].ModuleID {
			return fingerprinters[i].ModuleID < fingerprinters[j].ModuleID
		}
		if fingerprinters[i].Target != fingerprinters[j].Target {
			return fingerprinters[i].Target < fingerprinters[j].Target
		}
		return fingerprinters[i].Version < fingerprinters[j].Version
	})

	var semantics []probeSemantic
	if ruleset != nil {
		for _, entry := range ruleset.Entries {
			if entry.Type == "fingerprint" && !targets[entry.ID] {
				continue
			}
			if entry.Type != "fingerprint" && entry.Type != "detector" {
				continue
			}
			semantics = append(semantics, probeSemantic{
				Type:           entry.Type,
				ID:             entry.ID,
				Version:        entry.Version,
				SemanticSHA256: entry.SemanticSHA256,
			})
		}
	}
	sort.Slice(semantics, func(i, j int) bool {
		if semantics[i].Type != semantics[j].Type {
			return semantics[i].Type < semantics[j].Type
		}
		if semantics[i].ID != semantics[j].ID {
			return semantics[i].ID < semantics[j].ID
		}
		if semantics[i].Version != semantics[j].Version {
			return semantics[i].Version < semantics[j].Version
		}
		return semantics[i].SemanticSHA256 < semantics[j].SemanticSHA256
	})

	ports := append([]int(nil), report.Ports...)
	sort.Ints(ports)
	return networkProbeContract{
		Version:        probeContractVersion,
		Scanner:        "network-fingerprint",
		Targets:        report.Targets,
		Ports:          ports,
		Fingerprinters: fingerprinters,
		Semantics:      semantics,
	}
}

func buildProtocolProbeContract(report protoscan.ProbeReport) protocolProbeContract {
	protocols := make([]protoscan.ProtocolSurface, len(report.Protocols))
	for i, protocol := range report.Protocols {
		protocols[i] = protocol
		protocols[i].Ports = append([]int(nil), protocol.Ports...)
		sort.Ints(protocols[i].Ports)
	}
	sort.Slice(protocols, func(i, j int) bool {
		return protocols[i].Protocol < protocols[j].Protocol
	})
	return protocolProbeContract{
		Version:   probeContractVersion,
		Scanner:   "protocol-discovery",
		Targets:   report.Targets,
		Protocols: protocols,
	}
}

func identifyProbeContract(scope string, contract any) (probeContractIdentity, error) {
	digest, err := common.CanonicalJSONHash(contract)
	if err != nil {
		return probeContractIdentity{}, err
	}
	digest = "sha256:" + digest
	return probeContractIdentity{
		CoverageKey: ingest.CanonicalCoverageKey("scan", scope, digest),
		Digest:      digest,
	}, nil
}
