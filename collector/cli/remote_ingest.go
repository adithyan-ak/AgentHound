package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const (
	remoteIngestTimeout       = 5 * time.Minute
	remoteIngestResponseLimit = 16 << 20
)

type remoteIngestReceipt struct {
	result *ingest.IngestResult
	raw    []byte
}

func postRemoteIngest(
	ctx context.Context,
	serverURL string,
	artifact []byte,
) (*remoteIngestReceipt, error) {
	endpoint, err := resolveRemoteIngestEndpoint(serverURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(artifact),
	)
	if err != nil {
		return nil, fmt.Errorf("create ingest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: remoteIngestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ingest request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, remoteIngestResponseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read ingest response: %w", err)
	}
	if len(body) > remoteIngestResponseLimit {
		return nil, fmt.Errorf("ingest response exceeds %d bytes", remoteIngestResponseLimit)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, remoteIngestHTTPError(resp.StatusCode, body)
	}

	result, err := decodeRemoteIngestResult(body)
	if err != nil {
		return nil, err
	}
	return &remoteIngestReceipt{
		result: result,
		raw:    body,
	}, nil
}

func decodeRemoteIngestResult(body []byte) (*ingest.IngestResult, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("decode ingest response: %w", err)
	}
	for _, field := range []string{
		"scan_id",
		"outcome",
		"projection_status",
		"submitted",
		"write_rows",
		"findings",
		"graph_totals",
		"normalization_status",
		"collection",
		"identity",
		"duration",
	} {
		raw, exists := fields[field]
		if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf("decode ingest response: required field %q is missing or null", field)
		}
	}
	nestedRequirements := []struct {
		field    string
		required []string
	}{
		{field: "submitted", required: []string{"nodes", "edges"}},
		{field: "write_rows", required: []string{"nodes", "edges"}},
		{field: "collection", required: []string{"state", "coverage_keys", "outcomes"}},
		{field: "identity", required: []string{
			"collection_point_id",
			"network_context_id",
			"quality",
			"network_quality",
			"network_class",
			"recognition",
		}},
	}
	for _, requirement := range nestedRequirements {
		if err := requireRemoteIngestObjectFields(
			fields[requirement.field],
			requirement.field,
			requirement.required,
		); err != nil {
			return nil, err
		}
	}
	optionalArrayRequirements := []struct {
		field    string
		required []string
	}{
		{
			field:    "stages",
			required: []string{"name", "state", "required", "duration"},
		},
		{
			field: "normalization_warnings",
			required: []string{
				"code",
				"status",
				"message",
				"publication_unsafe",
			},
		},
		{
			field: "post_processing_stats",
			required: []string{
				"processor_name",
				"edges_created",
				"nodes_updated",
				"duration",
			},
		},
	}
	for _, requirement := range optionalArrayRequirements {
		raw, exists := fields[requirement.field]
		if !exists {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf(
				"decode ingest response: field %q must be an array when present",
				requirement.field,
			)
		}
		if err := requireRemoteIngestArrayObjectFields(
			raw,
			requirement.field,
			requirement.required,
		); err != nil {
			return nil, err
		}
	}
	if err := requireRemoteGraphSnapshotFields(fields["graph_totals"]); err != nil {
		return nil, err
	}
	var result ingest.IngestResult
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode ingest response: %w", err)
	}
	if err := validateRemoteIngestReceiptV1(&result); err != nil {
		return nil, fmt.Errorf("decode ingest response: invalid V1 receipt: %w", err)
	}
	return &result, nil
}

func requireRemoteGraphSnapshotFields(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("decode ingest response: graph_totals must be an object: %w", err)
	}
	for _, snapshot := range []string{"before", "after"} {
		value, exists := fields[snapshot]
		if !exists {
			return fmt.Errorf(
				"decode ingest response: required field %q is missing or null",
				"graph_totals."+snapshot,
			)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			continue
		}
		if err := requireRemoteIngestObjectFields(
			value,
			"graph_totals."+snapshot,
			[]string{"node_counts", "edge_counts", "total_nodes", "total_edges"},
		); err != nil {
			return err
		}
	}
	return nil
}

func requireRemoteIngestArrayObjectFields(
	raw json.RawMessage,
	path string,
	required []string,
) error {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf(
			"decode ingest response: %s must be an array: %w",
			path,
			err,
		)
	}
	for index, item := range items {
		if err := requireRemoteIngestObjectFields(
			item,
			fmt.Sprintf("%s[%d]", path, index),
			required,
		); err != nil {
			return err
		}
	}
	return nil
}

func requireRemoteIngestObjectFields(
	raw json.RawMessage,
	path string,
	required []string,
) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("decode ingest response: %s must be an object: %w", path, err)
	}
	for _, field := range required {
		value, exists := fields[field]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf(
				"decode ingest response: required field %q is missing or null",
				path+"."+field,
			)
		}
	}
	return nil
}

func validateRemoteIngestReceiptV1(result *ingest.IngestResult) error {
	if result == nil {
		return fmt.Errorf("result is null")
	}
	if strings.TrimSpace(result.ScanID) == "" {
		return fmt.Errorf("scan_id must not be empty")
	}
	switch result.Outcome {
	case ingest.OutcomeUnknown,
		ingest.OutcomeComplete,
		ingest.OutcomePartial,
		ingest.OutcomeFailed:
	default:
		return fmt.Errorf("outcome %q is invalid", result.Outcome)
	}
	switch result.ProjectionStatus {
	case "complete", "incomplete":
	default:
		return fmt.Errorf("projection_status %q is invalid", result.ProjectionStatus)
	}
	if (result.Outcome == ingest.OutcomeComplete) !=
		(result.ProjectionStatus == "complete") {
		return fmt.Errorf(
			"outcome %q is inconsistent with projection_status %q",
			result.Outcome,
			result.ProjectionStatus,
		)
	}
	if result.Submitted.Nodes < 0 || result.Submitted.Edges < 0 {
		return fmt.Errorf("submitted counts must be non-negative")
	}
	if result.WriteRows.Nodes < 0 || result.WriteRows.Edges < 0 {
		return fmt.Errorf("write_rows counts must be non-negative")
	}
	if result.Findings < 0 {
		return fmt.Errorf("findings must be non-negative")
	}
	if result.Duration < 0 {
		return fmt.Errorf("duration must be non-negative")
	}
	switch result.NormalizationStatus {
	case ingest.NormalizationStatusComplete, ingest.NormalizationStatusWarning,
		ingest.NormalizationStatusDegraded:
	default:
		return fmt.Errorf(
			"normalization_status %q is invalid",
			result.NormalizationStatus,
		)
	}
	if err := validateRemoteCollectionReport(&result.Collection); err != nil {
		return err
	}
	if err := validateRemoteIdentityResult(result.Identity); err != nil {
		return err
	}
	if err := validateRemoteNormalizationWarnings(result); err != nil {
		return err
	}
	if err := validateRemoteStages(result); err != nil {
		return err
	}
	if err := validateRemotePostProcessingStats(result); err != nil {
		return err
	}
	if result.PublishedRevision != nil && *result.PublishedRevision < 1 {
		return fmt.Errorf("published_revision must be at least 1")
	}
	if err := validateRemoteGraphTotals("graph_totals.before", result.GraphTotals.Before); err != nil {
		return err
	}
	if err := validateRemoteGraphTotals("graph_totals.after", result.GraphTotals.After); err != nil {
		return err
	}
	if result.ProjectionStatus == "complete" {
		if result.NormalizationStatus == ingest.NormalizationStatusDegraded {
			return fmt.Errorf("complete projection cannot use degraded normalization")
		}
		if result.PublishedRevision == nil {
			return fmt.Errorf("complete projection requires published_revision")
		}
		if result.GraphTotals.Before == nil || result.GraphTotals.After == nil {
			return fmt.Errorf("complete projection requires before and after graph totals")
		}
	}
	return nil
}

func validateRemoteNormalizationWarnings(result *ingest.IngestResult) error {
	expectedStatus := ingest.NormalizationStatusComplete
	for index, warning := range result.NormalizationWarnings {
		path := fmt.Sprintf("normalization_warnings[%d]", index)
		if strings.TrimSpace(warning.Code) == "" {
			return fmt.Errorf("%s.code must not be empty", path)
		}
		if strings.TrimSpace(warning.Message) == "" {
			return fmt.Errorf("%s.message must not be empty", path)
		}
		switch warning.Status {
		case ingest.NormalizationStatusWarning:
			if warning.PublicationUnsafe {
				return fmt.Errorf(
					"%s warning status cannot be publication-unsafe",
					path,
				)
			}
			if expectedStatus == ingest.NormalizationStatusComplete {
				expectedStatus = ingest.NormalizationStatusWarning
			}
		case ingest.NormalizationStatusDegraded:
			if !warning.PublicationUnsafe {
				return fmt.Errorf(
					"%s degraded status must be publication-unsafe",
					path,
				)
			}
			expectedStatus = ingest.NormalizationStatusDegraded
		default:
			return fmt.Errorf("%s.status %q is invalid", path, warning.Status)
		}
	}
	if result.NormalizationStatus != expectedStatus {
		return fmt.Errorf(
			"normalization_status %q is inconsistent with warnings status %q",
			result.NormalizationStatus,
			expectedStatus,
		)
	}
	return nil
}

func validateRemoteStages(result *ingest.IngestResult) error {
	for index, stage := range result.Stages {
		path := fmt.Sprintf("stages[%d]", index)
		if strings.TrimSpace(stage.Name) == "" {
			return fmt.Errorf("%s.name must not be empty", path)
		}
		if !validRemoteCollectionState(stage.State) {
			return fmt.Errorf("%s.state %q is invalid", path, stage.State)
		}
		if stage.Duration < 0 {
			return fmt.Errorf("%s.duration must be non-negative", path)
		}
		if stage.State == ingest.OutcomeComplete &&
			strings.TrimSpace(stage.Error) != "" {
			return fmt.Errorf("%s complete state cannot include an error", path)
		}
		if result.ProjectionStatus != "complete" {
			continue
		}
		if stage.Required && stage.State != ingest.OutcomeComplete {
			return fmt.Errorf(
				"complete projection has required stage %q in state %q",
				stage.Name,
				stage.State,
			)
		}
		if stage.Name == "publication" && stage.State != ingest.OutcomeComplete {
			return fmt.Errorf(
				"complete projection has publication stage in state %q",
				stage.State,
			)
		}
	}
	return nil
}

func validateRemotePostProcessingStats(result *ingest.IngestResult) error {
	for index, stat := range result.PostProcessingStats {
		path := fmt.Sprintf("post_processing_stats[%d]", index)
		if strings.TrimSpace(stat.ProcessorName) == "" {
			return fmt.Errorf("%s.processor_name must not be empty", path)
		}
		if stat.EdgesCreated < 0 || stat.NodesUpdated < 0 {
			return fmt.Errorf("%s counts must be non-negative", path)
		}
		if stat.Duration < 0 {
			return fmt.Errorf("%s.duration must be non-negative", path)
		}
		if result.ProjectionStatus == "complete" &&
			strings.TrimSpace(stat.Error) != "" {
			return fmt.Errorf(
				"complete projection cannot include %s.error",
				path,
			)
		}
	}
	return nil
}

func validateRemoteCollectionReport(report *ingest.CollectionReport) error {
	if report == nil {
		return fmt.Errorf("collection is null")
	}
	if !validRemoteCollectionState(report.State) {
		return fmt.Errorf("collection.state %q is invalid", report.State)
	}
	if len(report.CoverageKeys) == 0 {
		return fmt.Errorf("collection.coverage_keys must be a nonempty array")
	}
	if len(report.Outcomes) == 0 {
		return fmt.Errorf("collection.outcomes must be a nonempty array")
	}

	declared := make(map[string]bool, len(report.CoverageKeys))
	for index, key := range report.CoverageKeys {
		if !isCanonicalRemoteCoverageKey(key) {
			return fmt.Errorf(
				"collection.coverage_keys[%d] is not canonical",
				index,
			)
		}
		if declared[key] {
			return fmt.Errorf(
				"collection.coverage_keys[%d] duplicates %q",
				index,
				key,
			)
		}
		declared[key] = true
	}

	observed := make(map[string]bool, len(report.Outcomes))
	for index, outcome := range report.Outcomes {
		path := fmt.Sprintf("collection.outcomes[%d]", index)
		if !ingest.AllowedCollectors[outcome.Collector] {
			return fmt.Errorf("%s.collector %q is invalid", path, outcome.Collector)
		}
		if !isCanonicalRemoteCoverageKey(outcome.CoverageKey) {
			return fmt.Errorf("%s.coverage_key is not canonical", path)
		}
		if !declared[outcome.CoverageKey] {
			return fmt.Errorf("%s.coverage_key is not declared", path)
		}
		if strings.Split(outcome.CoverageKey, ":")[0] != outcome.Collector {
			return fmt.Errorf("%s.coverage_key has the wrong collector prefix", path)
		}
		if outcome.ParentCoverageKey != "" {
			if !isCanonicalRemoteCoverageKey(outcome.ParentCoverageKey) ||
				!declared[outcome.ParentCoverageKey] ||
				outcome.ParentCoverageKey == outcome.CoverageKey {
				return fmt.Errorf("%s.parent_coverage_key is invalid", path)
			}
		}
		if strings.TrimSpace(outcome.Target) == "" {
			return fmt.Errorf("%s.target must not be empty", path)
		}
		if strings.TrimSpace(outcome.Method) == "" {
			return fmt.Errorf("%s.method must not be empty", path)
		}
		if !validRemoteCollectionState(outcome.State) {
			return fmt.Errorf("%s.state %q is invalid", path, outcome.State)
		}
		if outcome.Items < 0 {
			return fmt.Errorf("%s.items must be non-negative", path)
		}
		observed[outcome.CoverageKey] = true
	}
	for key := range declared {
		if !observed[key] {
			return fmt.Errorf("collection.outcomes has no outcome for %q", key)
		}
	}
	if aggregate := ingest.AggregateOutcomeState(report.Outcomes); aggregate != report.State {
		return fmt.Errorf(
			"collection.state %q does not match aggregate outcome %q",
			report.State,
			aggregate,
		)
	}

	roots := make(map[string]bool, len(report.AuthoritativeRoots))
	for rootIndex, root := range report.AuthoritativeRoots {
		path := fmt.Sprintf("collection.authoritative_roots[%d]", rootIndex)
		if !isCanonicalRemoteCoverageKey(root.CoverageKey) ||
			!declared[root.CoverageKey] {
			return fmt.Errorf("%s.coverage_key is invalid", path)
		}
		if roots[root.CoverageKey] {
			return fmt.Errorf("%s.coverage_key is duplicated", path)
		}
		roots[root.CoverageKey] = true
		if root.ChildCoverageKeys == nil {
			return fmt.Errorf("%s.child_coverage_keys must be an array", path)
		}
		children := make(map[string]bool, len(root.ChildCoverageKeys))
		for childIndex, child := range root.ChildCoverageKeys {
			if !isCanonicalRemoteCoverageKey(child) ||
				!declared[child] ||
				child == root.CoverageKey ||
				children[child] {
				return fmt.Errorf(
					"%s.child_coverage_keys[%d] is invalid",
					path,
					childIndex,
				)
			}
			children[child] = true
		}
		instructionRoot := false
		for _, method := range []string{
			ingest.InstructionMethodExactUser,
			ingest.InstructionMethodExactProject,
			ingest.InstructionMethodDeep,
		} {
			if ingest.InstructionRootMatchesMethod(root.CoverageKey, method) {
				instructionRoot = true
				break
			}
		}
		if !instructionRoot {
			if root.RegistryContract != nil {
				return fmt.Errorf(
					"%s.registry_contract must be omitted for non-instruction roots",
					path,
				)
			}
			continue
		}
		current := ingest.CurrentInstructionRegistryContract()
		if root.RegistryContract == nil ||
			!root.RegistryContract.Equal(current) {
			return fmt.Errorf(
				"%s.registry_contract must match the current instruction registry",
				path,
			)
		}
	}
	return nil
}

func validRemoteCollectionState(state ingest.OutcomeState) bool {
	switch state {
	case ingest.OutcomeUnknown,
		ingest.OutcomeNotApplicable,
		ingest.OutcomeComplete,
		ingest.OutcomePartial,
		ingest.OutcomeFailed,
		ingest.OutcomeTruncated:
		return true
	default:
		return false
	}
}

func isCanonicalRemoteCoverageKey(key string) bool {
	parts := strings.Split(key, ":")
	return len(parts) == 4 &&
		ingest.AllowedCollectors[parts[0]] &&
		parts[1] != "" &&
		parts[2] == "sha256" &&
		isLowerHexSHA256(parts[3])
}

func validateRemoteIdentityResult(identity ingest.IngestIdentityResult) error {
	if !isCanonicalSHA256(identity.CollectionPointID) {
		return fmt.Errorf("identity.collection_point_id is not canonical")
	}
	if !isCanonicalSHA256(identity.NetworkContextID) {
		return fmt.Errorf("identity.network_context_id is not canonical")
	}
	if identity.Quality != ingest.IdentityQualityStrong &&
		identity.Quality != ingest.IdentityQualityWeak {
		return fmt.Errorf("identity.quality %q is invalid", identity.Quality)
	}
	if identity.NetworkQuality != ingest.IdentityQualityStrong &&
		identity.NetworkQuality != ingest.IdentityQualityUnknown {
		return fmt.Errorf(
			"identity.network_quality %q is invalid",
			identity.NetworkQuality,
		)
	}
	switch identity.NetworkClass {
	case ingest.NetworkClassUnknown,
		ingest.NetworkClassOffline,
		ingest.NetworkClassPrivate,
		ingest.NetworkClassPublic,
		ingest.NetworkClassMixed:
	default:
		return fmt.Errorf("identity.network_class %q is invalid", identity.NetworkClass)
	}
	switch identity.Recognition {
	case "new", "recognized", "unknown":
	default:
		return fmt.Errorf("identity.recognition %q is invalid", identity.Recognition)
	}
	return nil
}

func isCanonicalSHA256(value string) bool {
	return strings.HasPrefix(value, "sha256:") &&
		isLowerHexSHA256(strings.TrimPrefix(value, "sha256:"))
}

func isLowerHexSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validateRemoteGraphTotals(path string, totals *ingest.GraphTotals) error {
	if totals == nil {
		return nil
	}
	if totals.NodeCounts == nil {
		return fmt.Errorf("%s.node_counts must be an object", path)
	}
	if totals.EdgeCounts == nil {
		return fmt.Errorf("%s.edge_counts must be an object", path)
	}
	if totals.TotalNodes < 0 || totals.TotalEdges < 0 {
		return fmt.Errorf("%s totals must be non-negative", path)
	}
	for kind, count := range totals.NodeCounts {
		if count < 0 {
			return fmt.Errorf("%s.node_counts[%q] must be non-negative", path, kind)
		}
	}
	for kind, count := range totals.EdgeCounts {
		if count < 0 {
			return fmt.Errorf("%s.edge_counts[%q] must be non-negative", path, kind)
		}
	}
	return nil
}

func resolveRemoteIngestEndpoint(serverURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return "", fmt.Errorf("invalid --ingest URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid --ingest URL: scheme must be http or https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid --ingest URL: provide a server base URL without credentials, query, or fragment")
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	switch path {
	case "":
		parsed.Path = "/api/v1/ingest"
		parsed.RawPath = ""
	case "/api/v1/ingest":
		parsed.Path = path
		parsed.RawPath = ""
	default:
		return "", fmt.Errorf("invalid --ingest URL: path must be empty or /api/v1/ingest")
	}
	return parsed.String(), nil
}

func remoteIngestHTTPError(status int, body []byte) error {
	var response struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &response); err == nil && response.Error.Message != "" {
		if response.Error.Code != "" {
			return fmt.Errorf("ingest failed with HTTP %d (%s): %s", status, response.Error.Code, response.Error.Message)
		}
		return fmt.Errorf("ingest failed with HTTP %d: %s", status, response.Error.Message)
	}
	return fmt.Errorf("ingest failed with HTTP %d", status)
}

func writeRemoteIngestResult(
	w io.Writer,
	receipt *remoteIngestReceipt,
	artifactPath string,
	fullJSON bool,
) error {
	if receipt == nil || receipt.result == nil {
		return fmt.Errorf("ingest returned no result")
	}
	result := receipt.result
	if err := validateRemoteIngestReceiptV1(result); err != nil {
		return fmt.Errorf("invalid V1 ingest receipt: %w", err)
	}
	if fullJSON {
		raw := receipt.raw
		if len(raw) == 0 {
			var err error
			raw, err = json.Marshal(result)
			if err != nil {
				return fmt.Errorf("encode ingest result: %w", err)
			}
		}
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, raw, "", "  "); err != nil {
			return fmt.Errorf("format ingest result: %w", err)
		}
		if err := formatted.WriteByte('\n'); err != nil {
			return fmt.Errorf("format ingest result: %w", err)
		}
		if _, err := w.Write(formatted.Bytes()); err != nil {
			return fmt.Errorf("write ingest result: %w", err)
		}
		return nil
	}

	complete := remoteIngestComplete(result)
	heading := "Ingest complete"
	if !complete {
		heading = "Ingest incomplete"
	} else if remoteResultCoverageLimited(result) {
		heading = "Ingest complete with coverage limitations"
	}
	findings := strconv.Itoa(result.Findings)
	if _, err := fmt.Fprintf(
		w,
		"%s:\n\n  Scan ID:   %s\n  Artifact:  %s\n  Nodes:     %d\n  Edges:     %d\n  Findings:  %s\n  Duration:  %s\n",
		heading,
		result.ScanID,
		artifactPath,
		result.Submitted.Nodes,
		result.Submitted.Edges,
		findings,
		result.Duration.Round(time.Millisecond),
	); err != nil {
		return fmt.Errorf("write ingest result: %w", err)
	}
	return nil
}

func remoteResultCoverageLimited(result *ingest.IngestResult) bool {
	if result == nil {
		return false
	}
	if ingest.CoverageLimited(&result.Collection) {
		return true
	}
	for _, warning := range result.Warnings {
		if warning == ingest.CoverageLimitationWarning {
			return true
		}
	}
	return false
}

func validateRemoteIngestScanID(result *ingest.IngestResult, expectedScanID string) error {
	if result == nil {
		return fmt.Errorf("ingest returned no result")
	}
	if result.ScanID != expectedScanID {
		return fmt.Errorf(
			"ingest receipt scan_id %q does not match submitted scan_id %q",
			result.ScanID,
			expectedScanID,
		)
	}
	return nil
}

func validateRemoteIngestResult(result *ingest.IngestResult) error {
	if result == nil {
		return fmt.Errorf("ingest returned no result")
	}
	if err := validateRemoteIngestReceiptV1(result); err != nil {
		return fmt.Errorf("invalid V1 ingest receipt: %w", err)
	}
	if remoteIngestComplete(result) {
		return nil
	}
	return fmt.Errorf(
		"ingest did not publish a complete projection: outcome=%s projection=%s",
		result.Outcome,
		result.ProjectionStatus,
	)
}

func remoteIngestComplete(result *ingest.IngestResult) bool {
	return result != nil &&
		result.Outcome == ingest.OutcomeComplete &&
		result.ProjectionStatus == "complete" &&
		result.PublishedRevision != nil &&
		*result.PublishedRevision >= 1
}
