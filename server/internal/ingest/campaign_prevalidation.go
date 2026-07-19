package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

const (
	campaignRejectionGenericIngestInvalid  = "generic_ingest_invalid"
	campaignRejectionArtifactMissing       = "artifact_missing"
	campaignRejectionArtifactMalformed     = "artifact_malformed"
	campaignRejectionArtifactContract      = "artifact_contract_invalid"
	campaignRejectionEnvelopeContract      = "envelope_contract_invalid"
	campaignRejectionEvidenceContract      = "evidence_contract_invalid"
	campaignRejectionTopologyMismatch      = "current_topology_mismatch"
	campaignRejectionValidationUnavailable = "current_topology_unavailable"

	maxCampaignArtifactBytes = 64 * 1024
)

var campaignEvidencePropertyKeys = map[string]bool{
	"scan_id": true, "last_seen": true, "is_composite": true,
	"confidence": true, "risk_weight": true,
	campaign.PropScenarioID: true, campaign.PropScenarioVersion: true,
	campaign.PropRunID: true, campaign.PropEngagementID: true,
	campaign.PropOracleType: true, campaign.PropOutcome: true,
	campaign.PropControlStage: true, campaign.PropControlStatus: true,
	campaign.PropControlAddressed: true, campaign.PropAuthedStage: true,
	campaign.PropAuthedStatus: true, campaign.PropAuthedAddressed: true,
	campaign.PropVerifiedAt: true, campaign.PropWitnessSchema: true,
	campaign.PropTopologyVersion: true, campaign.PropPublicationRevision: true,
	campaign.PropPredictedEdgeKind: true, campaign.PropAgentID: true,
	campaign.PropAgentKind: true, campaign.PropCredentialID: true,
	campaign.PropCredentialKind: true, campaign.PropCredentialValueHash: true,
	campaign.PropCredentialMergeKey: true, campaign.PropServerID: true,
	campaign.PropServerKind: true, campaign.PropResourceID: true,
	campaign.PropResourceKind: true, campaign.PropResourceIdentity: true,
	campaign.PropEvidenceNodeIDs: true, campaign.PropEvidenceNodeKinds: true,
	campaign.PropWitnessFingerprint: true,
}

// CampaignArtifactRejectionError exposes only the random audit handle and fixed
// rejection codes. It never includes submitted artifact values or a raw digest.
type CampaignArtifactRejectionError struct {
	RejectionID string
	ReasonCodes []string
}

func (e *CampaignArtifactRejectionError) Error() string {
	return fmt.Sprintf(
		"campaign artifact rejected: rejection_id=%s reason_codes=%s",
		e.RejectionID,
		strings.Join(e.ReasonCodes, ","),
	)
}

type campaignAuditIdentity struct {
	runID           string
	scenarioID      string
	scenarioVersion int
	outcome         string
}

func (p *Pipeline) prevalidateCampaignArtifact(
	ctx context.Context,
	data *sdkingest.IngestData,
) error {
	if !isCampaignSubmission(data) {
		return nil
	}

	identity := campaignAuditIdentityFromData(data)
	artifact, code := decodeCampaignArtifact(data)
	if code == "" {
		identity = campaignAuditIdentityFromArtifact(artifact)
		code = validateCampaignEnvelope(data, artifact)
	}
	if code == "" {
		code = validateCampaignCurrentTopology(ctx, p.graphDB, artifact)
	}
	if code == "" {
		return nil
	}
	return p.rejectCampaignArtifact(ctx, identity, code)
}

func (p *Pipeline) rejectCampaignArtifact(
	ctx context.Context,
	identity campaignAuditIdentity,
	code string,
) error {
	rejectionID := uuid.NewString()
	reasonCodes := []string{code}
	if p.scanStore == nil {
		return fmt.Errorf(
			"campaign artifact rejected but rejection audit is unavailable: rejection_id=%s reason_codes=%s",
			rejectionID,
			code,
		)
	}
	if err := p.scanStore.RecordCampaignRejection(ctx, appdb.CampaignRejectionAudit{
		RejectionID:     rejectionID,
		RunID:           identity.runID,
		ScenarioID:      identity.scenarioID,
		ScenarioVersion: identity.scenarioVersion,
		Outcome:         identity.outcome,
		ReasonCodes:     reasonCodes,
	}); err != nil {
		return fmt.Errorf(
			"campaign artifact rejected but rejection audit failed: rejection_id=%s reason_codes=%s",
			rejectionID,
			code,
		)
	}
	return &CampaignArtifactRejectionError{
		RejectionID: rejectionID,
		ReasonCodes: reasonCodes,
	}
}

func isCampaignSubmission(data *sdkingest.IngestData) bool {
	if data == nil {
		return false
	}
	for key := range data.Meta.Extra {
		if key == campaign.EvidenceArtifactMetadataKey ||
			strings.HasPrefix(key, "campaign_") {
			return true
		}
	}
	if data.Meta.Collection != nil {
		for _, outcome := range data.Meta.Collection.Outcomes {
			if strings.HasPrefix(outcome.Method, "campaign:") {
				return true
			}
		}
	}
	for _, edge := range data.Graph.Edges {
		if edge.Kind == "CREDENTIAL_REACH_VERIFIED" ||
			edge.Kind == "PUBLIC_ACCESS_OBSERVED" {
			return true
		}
	}
	return false
}

func decodeCampaignArtifact(
	data *sdkingest.IngestData,
) (campaign.EvidenceArtifact, string) {
	if len(data.Meta.Extra) != 1 {
		return campaign.EvidenceArtifact{}, campaignRejectionEnvelopeContract
	}
	raw, ok := data.Meta.Extra[campaign.EvidenceArtifactMetadataKey]
	if !ok {
		return campaign.EvidenceArtifact{}, campaignRejectionArtifactMissing
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > maxCampaignArtifactBytes {
		return campaign.EvidenceArtifact{}, campaignRejectionArtifactMalformed
	}
	var artifact campaign.EvidenceArtifact
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&artifact); err != nil {
		return campaign.EvidenceArtifact{}, campaignRejectionArtifactMalformed
	}
	if decoder.More() {
		return campaign.EvidenceArtifact{}, campaignRejectionArtifactMalformed
	}
	if err := artifact.Validate(); err != nil {
		return artifact, campaignRejectionArtifactContract
	}
	return artifact, ""
}

func validateCampaignEnvelope(
	data *sdkingest.IngestData,
	artifact campaign.EvidenceArtifact,
) string {
	if data.Meta.Collector != "scan" || data.Meta.Collection == nil {
		return campaignRejectionEnvelopeContract
	}
	coverageKey := campaignCoverageKey(artifact)
	collection := data.Meta.Collection
	expectedState := sdkingest.OutcomePartial
	if artifact.Outcome.Definitive() {
		expectedState = sdkingest.OutcomeComplete
	}
	if collection.State != expectedState ||
		len(collection.CoverageKeys) != 1 ||
		collection.CoverageKeys[0] != coverageKey ||
		len(collection.AuthoritativeRoots) != 0 ||
		len(collection.Outcomes) != 1 {
		return campaignRejectionEnvelopeContract
	}
	outcome := collection.Outcomes[0]
	if outcome.Collector != "scan" ||
		outcome.CoverageKey != coverageKey ||
		outcome.Target != artifact.Witness.ServerID ||
		outcome.Method != "campaign:"+artifact.ScenarioID ||
		outcome.State != expectedState {
		return campaignRejectionEnvelopeContract
	}

	edgeKind, emitsEdge := artifact.Outcome.EdgeKind()
	if !emitsEdge {
		if outcome.Items != 0 ||
			len(data.Graph.Nodes) != 0 ||
			len(data.Graph.Edges) != 0 {
			return campaignRejectionEnvelopeContract
		}
		return ""
	}
	if outcome.Items != 1 ||
		len(data.Graph.Nodes) != 2 ||
		len(data.Graph.Edges) != 1 {
		return campaignRejectionEnvelopeContract
	}
	if !validateCampaignEvidenceGraph(data, artifact, coverageKey, edgeKind) {
		return campaignRejectionEvidenceContract
	}
	return ""
}

func validateCampaignEvidenceGraph(
	data *sdkingest.IngestData,
	artifact campaign.EvidenceArtifact,
	coverageKey, edgeKind string,
) bool {
	edge := data.Graph.Edges[0]
	sourceID := artifact.Witness.AgentID
	sourceKind := "AgentInstance"
	if edgeKind == "PUBLIC_ACCESS_OBSERVED" {
		sourceID = artifact.Witness.ServerID
		sourceKind = "MCPServer"
	}
	if edge.Source != sourceID ||
		edge.Target != artifact.Witness.ResourceID ||
		edge.Kind != edgeKind ||
		edge.SourceKind != sourceKind ||
		edge.TargetKind != "MCPResource" ||
		edge.ObservationSemantics != "" ||
		!equalStrings(edge.ObservationDomains, []string{coverageKey}) {
		return false
	}

	expectedNodes := map[string]string{
		sourceID:                    sourceKind,
		artifact.Witness.ResourceID: "MCPResource",
	}
	for _, node := range data.Graph.Nodes {
		if expectedNodes[node.ID] != sdkingest.ConcreteNodeKind(node.Kinds) ||
			node.PropertySemantics != sdkingest.NodePropertySemanticsReferenceOnly ||
			len(node.Properties) != 0 ||
			!equalStrings(node.ObservationDomains, []string{coverageKey}) {
			return false
		}
		delete(expectedNodes, node.ID)
	}
	if len(expectedNodes) != 0 {
		return false
	}

	if len(edge.Properties) != len(campaignEvidencePropertyKeys) {
		return false
	}
	for key := range edge.Properties {
		if !campaignEvidencePropertyKeys[key] {
			return false
		}
	}
	isComposite, compositeOK := edge.Properties["is_composite"].(bool)
	confidence, confidenceOK := numericFloat(edge.Properties["confidence"])
	riskWeight, riskWeightOK := numericFloat(edge.Properties["risk_weight"])
	if stringProperty(edge.Properties, "scan_id") != data.Meta.ScanID ||
		!compositeOK || isComposite ||
		!confidenceOK || confidence != 1 ||
		!riskWeightOK || riskWeight != 0.1 {
		return false
	}
	if _, err := time.Parse(
		time.RFC3339,
		stringProperty(edge.Properties, "last_seen"),
	); err != nil {
		return false
	}
	evidence, fingerprint, err := campaignEvidenceFromProperties(edge.Properties)
	if err != nil ||
		!reflect.DeepEqual(evidence.Artifact(), artifact) ||
		evidence.Witness.Fingerprint() != fingerprint {
		return false
	}
	return true
}

func campaignEvidenceFromProperties(
	properties map[string]any,
) (campaign.Evidence, string, error) {
	witness := campaign.Witness{
		SchemaVersion:                intProperty(properties, campaign.PropWitnessSchema),
		TopologyNormalizationVersion: intProperty(properties, campaign.PropTopologyVersion),
		PublicationRevision:          intProperty(properties, campaign.PropPublicationRevision),
		PredictedEdgeKind:            stringProperty(properties, campaign.PropPredictedEdgeKind),
		AgentID:                      stringProperty(properties, campaign.PropAgentID),
		AgentKind:                    stringProperty(properties, campaign.PropAgentKind),
		CredentialID:                 stringProperty(properties, campaign.PropCredentialID),
		CredentialKind:               stringProperty(properties, campaign.PropCredentialKind),
		CredentialValueHash:          stringProperty(properties, campaign.PropCredentialValueHash),
		CredentialMergeKey:           stringProperty(properties, campaign.PropCredentialMergeKey),
		ServerID:                     stringProperty(properties, campaign.PropServerID),
		ServerKind:                   stringProperty(properties, campaign.PropServerKind),
		ResourceID:                   stringProperty(properties, campaign.PropResourceID),
		ResourceKind:                 stringProperty(properties, campaign.PropResourceKind),
		ResourceIdentityInput:        stringProperty(properties, campaign.PropResourceIdentity),
		EvidenceNodeIDs:              stringSliceProperty(properties, campaign.PropEvidenceNodeIDs),
		EvidenceNodeKinds:            stringSliceProperty(properties, campaign.PropEvidenceNodeKinds),
	}
	evidence := campaign.Evidence{
		ScenarioID:       stringProperty(properties, campaign.PropScenarioID),
		ScenarioVersion:  intProperty(properties, campaign.PropScenarioVersion),
		RunID:            stringProperty(properties, campaign.PropRunID),
		EngagementID:     stringProperty(properties, campaign.PropEngagementID),
		OracleType:       stringProperty(properties, campaign.PropOracleType),
		Outcome:          campaign.Outcome(stringProperty(properties, campaign.PropOutcome)),
		ControlStage:     campaign.ProbeStage(stringProperty(properties, campaign.PropControlStage)),
		ControlStatus:    campaign.ProbeStatus(stringProperty(properties, campaign.PropControlStatus)),
		ControlAddressed: boolProperty(properties, campaign.PropControlAddressed),
		AuthedStage:      campaign.ProbeStage(stringProperty(properties, campaign.PropAuthedStage)),
		AuthedStatus:     campaign.ProbeStatus(stringProperty(properties, campaign.PropAuthedStatus)),
		AuthedAddressed:  boolProperty(properties, campaign.PropAuthedAddressed),
		VerifiedAt:       stringProperty(properties, campaign.PropVerifiedAt),
		Witness:          witness,
	}
	if err := evidence.Artifact().Validate(); err != nil {
		return campaign.Evidence{}, "", err
	}
	if strings.TrimSpace(evidence.EngagementID) == "" ||
		len(evidence.EngagementID) > 128 {
		return campaign.Evidence{}, "", fmt.Errorf("campaign engagement_id is invalid")
	}
	if _, err := time.Parse(time.RFC3339, evidence.VerifiedAt); err != nil {
		return campaign.Evidence{}, "", fmt.Errorf("campaign verified_at is invalid")
	}
	fingerprint := stringProperty(properties, campaign.PropWitnessFingerprint)
	if fingerprint == "" {
		return campaign.Evidence{}, "", fmt.Errorf("campaign witness fingerprint is missing")
	}
	return evidence, fingerprint, nil
}

const campaignCurrentTopologyValidationQuery = `
MATCH (a:AgentInstance {objectid: $agent_id})
MATCH (r:MCPResource {objectid: $resource_id})
WHERE r.uri = $resource_identity_input
MATCH (s:MCPServer {objectid: $server_id})-[:PROVIDES_RESOURCE]->(r)
WHERE toLower(coalesce(s.transport, '')) = 'http'
MATCH (c:Credential {objectid: $credential_id})
WHERE c.value_hash = $credential_value_hash
  AND c.merge_key = $credential_merge_key
MATCH (a)-[e:CAN_REACH]->(r)
WHERE coalesce(e.is_composite, false) = true
  AND e.evidence_node_ids = $evidence_node_ids
WITH e
UNWIND range(0, size($evidence_node_ids) - 1) AS evidence_index
MATCH (evidence_node)
WHERE evidence_node.objectid = $evidence_node_ids[evidence_index]
  AND $evidence_node_kinds[evidence_index] IN labels(evidence_node)
WITH e, collect(DISTINCT evidence_index) AS matched_indices
WHERE size(matched_indices) = size($evidence_node_ids)
RETURN count(DISTINCT e) AS matches`

func validateCampaignCurrentTopology(
	ctx context.Context,
	db graph.GraphDB,
	artifact campaign.EvidenceArtifact,
) string {
	if db == nil {
		return campaignRejectionValidationUnavailable
	}
	witness := artifact.Witness
	rows, err := db.Query(ctx, campaignCurrentTopologyValidationQuery, map[string]any{
		"agent_id":                witness.AgentID,
		"resource_id":             witness.ResourceID,
		"resource_identity_input": witness.ResourceIdentityInput,
		"server_id":               witness.ServerID,
		"credential_id":           witness.CredentialID,
		"credential_value_hash":   witness.CredentialValueHash,
		"credential_merge_key":    witness.CredentialMergeKey,
		"evidence_node_ids":       append([]string(nil), witness.EvidenceNodeIDs...),
		"evidence_node_kinds":     append([]string(nil), witness.EvidenceNodeKinds...),
	})
	if err != nil {
		return campaignRejectionValidationUnavailable
	}
	for _, row := range rows {
		if matches, ok := int64Property(row, "matches"); ok && matches > 0 {
			return ""
		}
	}
	return campaignRejectionTopologyMismatch
}

func campaignCoverageKey(artifact campaign.EvidenceArtifact) string {
	witness := artifact.Witness
	scope := strings.Join([]string{
		artifact.ScenarioID,
		strconv.Itoa(artifact.ScenarioVersion),
		witness.AgentID,
		witness.CredentialID,
		witness.ServerID,
		witness.ResourceID,
	}, "\x00")
	return sdkingest.CanonicalCoverageKey("scan", "campaign", scope)
}

func campaignAuditIdentityFromData(
	data *sdkingest.IngestData,
) campaignAuditIdentity {
	identity := campaignAuditIdentity{
		runID:      "invalid",
		scenarioID: "unknown",
		outcome:    "unknown",
	}
	raw, ok := data.Meta.Extra[campaign.EvidenceArtifactMetadataKey]
	if !ok {
		return identity
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > maxCampaignArtifactBytes {
		return identity
	}
	var fields struct {
		RunID           string           `json:"run_id"`
		ScenarioID      string           `json:"scenario_id"`
		ScenarioVersion int              `json:"scenario_version"`
		Outcome         campaign.Outcome `json:"outcome"`
	}
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return identity
	}
	identity.runID = sanitizeOpaqueRunID(fields.RunID)
	if fields.ScenarioID == "cred-reach" {
		identity.scenarioID = fields.ScenarioID
	}
	if fields.ScenarioVersion > 0 && fields.ScenarioVersion <= 1000 {
		identity.scenarioVersion = fields.ScenarioVersion
	}
	if validAuditOutcome(fields.Outcome) {
		identity.outcome = string(fields.Outcome)
	}
	return identity
}

func campaignAuditIdentityFromArtifact(
	artifact campaign.EvidenceArtifact,
) campaignAuditIdentity {
	identity := campaignAuditIdentity{
		runID:           sanitizeOpaqueRunID(artifact.RunID),
		scenarioID:      "unknown",
		scenarioVersion: artifact.ScenarioVersion,
		outcome:         "unknown",
	}
	if artifact.ScenarioID == "cred-reach" {
		identity.scenarioID = artifact.ScenarioID
	}
	if artifact.ScenarioVersion < 0 || artifact.ScenarioVersion > 1000 {
		identity.scenarioVersion = 0
	}
	if validAuditOutcome(artifact.Outcome) {
		identity.outcome = string(artifact.Outcome)
	}
	return identity
}

func sanitizeOpaqueRunID(value string) string {
	if value == "" || len(value) > 128 {
		return "invalid"
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '.' {
			continue
		}
		return "invalid"
	}
	return value
}

func validAuditOutcome(outcome campaign.Outcome) bool {
	switch outcome {
	case campaign.OutcomeCredentialGatedReachVerified,
		campaign.OutcomeAnonymousAccessObserved,
		campaign.OutcomeAnonymousAccessCredentialRejected,
		campaign.OutcomeNotObserved,
		campaign.OutcomeIndeterminate:
		return true
	default:
		return false
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func stringProperty(properties map[string]any, key string) string {
	value, _ := properties[key].(string)
	return value
}

func intProperty(properties map[string]any, key string) int {
	switch value := properties[key].(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		if value == float64(int(value)) {
			return int(value)
		}
	}
	return 0
}

func int64Property(properties map[string]any, key string) (int64, bool) {
	switch value := properties[key].(type) {
	case int:
		return int64(value), true
	case int32:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		if value == float64(int64(value)) {
			return int64(value), true
		}
	}
	return 0, false
}

func boolProperty(properties map[string]any, key string) bool {
	value, _ := properties[key].(bool)
	return value
}

func stringSliceProperty(properties map[string]any, key string) []string {
	switch values := properties[key].(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil
			}
			result = append(result, text)
		}
		return result
	default:
		return nil
	}
}
