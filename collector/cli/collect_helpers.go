package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	collectoridentity "github.com/adithyan-ak/agenthound/collector/internal/identity"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

var deriveCollectionIdentity = collectoridentity.Derive

func prepareCollectorArtifact(data *ingest.IngestData) error {
	if data == nil {
		return fmt.Errorf("ingest data is nil")
	}
	data.Meta.Identity = deriveCollectionIdentity(data.Meta.ScanID)
	ingest.EnsureCoverageParentage(data.Meta.Collection)
	if err := validateCollectorCoverage(data.Meta.Collection); err != nil {
		return err
	}
	return data.Meta.Identity.Validate()
}

// validateCollectorCoverage enforces the two ingest invariants the unified
// scan itself composes: every outcome key is declared, and its collector owns
// that key prefix. Module reports are still validated fully by the server.
func validateCollectorCoverage(report *ingest.CollectionReport) error {
	if report == nil {
		return fmt.Errorf("collection report is required")
	}
	declared := make(map[string]bool, len(report.CoverageKeys))
	covered := make(map[string]bool, len(report.Outcomes))
	for _, key := range report.CoverageKeys {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("collection coverage key is empty")
		}
		if declared[key] {
			return fmt.Errorf("collection coverage key %q is duplicated", key)
		}
		declared[key] = true
	}
	for _, outcome := range report.Outcomes {
		if !declared[outcome.CoverageKey] {
			return fmt.Errorf("collection outcome key %q is not declared", outcome.CoverageKey)
		}
		prefix, _, present := strings.Cut(outcome.CoverageKey, ":")
		if !present || prefix != outcome.Collector {
			return fmt.Errorf(
				"collection outcome key %q is not owned by collector %q",
				outcome.CoverageKey,
				outcome.Collector,
			)
		}
		covered[outcome.CoverageKey] = true
	}
	for key := range declared {
		if !covered[key] {
			return fmt.Errorf("collection coverage key %q has no outcome", key)
		}
	}
	return nil
}

func marshalCollectorArtifact(data *ingest.IngestData) ([]byte, error) {
	if err := prepareCollectorArtifact(data); err != nil {
		return nil, fmt.Errorf("prepare ingest v1 artifact: %w", err)
	}
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal JSON: %w", err)
	}
	var decoded ingest.IngestData
	if err := ingest.DecodeStrict(bytes.NewReader(encoded), &decoded); err != nil {
		return nil, fmt.Errorf("validate encoded ingest v1 artifact: %w", err)
	}
	return encoded, nil
}
