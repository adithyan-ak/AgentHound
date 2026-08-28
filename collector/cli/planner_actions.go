package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	a2acollector "github.com/adithyan-ak/agenthound/modules/a2a"
	"github.com/adithyan-ak/agenthound/modules/credreach"
	"github.com/adithyan-ak/agenthound/sdk/action"
	icollector "github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

type serviceCollectAction struct {
	timeout time.Duration
}

func (serviceCollectAction) ID() string { return "service.collect" }

var serviceNodeKinds = map[string]string{
	"LiteLLMGateway":    "litellm",
	"OpenWebUIInstance": "openwebui",
	"JupyterServer":     "jupyter",
	"QdrantInstance":    "qdrant",
	"MLflowServer":      "mlflow",
	"OllamaInstance":    "ollama",
}

var serviceInventoryNames = map[string]string{
	"litellm": "inventory", "openwebui": "backends", "jupyter": "contents",
	"qdrant": "collections", "mlflow": "model_registry", "ollama": "models",
}

func (a serviceCollectAction) Candidates(view View) []Candidate {
	var candidates []Candidate
	seen := make(map[string]bool)
	for kind, service := range serviceNodeKinds {
		for _, node := range view.ByKind[kind] {
			endpoint, _ := node.Properties["endpoint"].(string)
			if strings.TrimSpace(endpoint) == "" {
				continue
			}
			mod, ok := module.GetByTarget(service, action.Collect)
			if !ok {
				continue
			}
			base := Candidate{
				ModuleID: mod.ID(), Target: action.Target{
					Kind: "url", Address: endpoint,
					Meta: map[string]string{"url": endpoint, "node_id": node.ID, "service_kind": service},
				},
				Inputs: map[string]string{
					"service": service, "node_id": node.ID,
					"inventory_name":      serviceInventoryNames[service],
					"observation_domains": strings.Join(node.ObservationDomains, "\x1f"),
				},
			}
			// Deep Qdrant collection already includes base inventory, so schedule
			// one combined call. Deep active Ollama likewise runs base inventory
			// through the embedding action; stealth keeps the ordinary read-only
			// call because compute is intentionally disabled.
			combineWithDeep := view.Deep && service == "qdrant"
			deferBaseToEmbedding := view.Deep && !view.Stealth && service == "ollama"
			if service != "litellm" && !deferBaseToEmbedding {
				candidate := base
				candidate.Priority = 2
				candidate.Key = candidateKey(mod.ID(), endpoint, "", "", view.Deep)
				if combineWithDeep {
					candidate.Inputs = cloneStringMap(base.Inputs)
					candidate.Inputs["deep"] = "true"
					candidate.Key = candidateKey(mod.ID()+".deep", endpoint, "", "", true)
				}
				if !seen[candidate.Key] {
					seen[candidate.Key] = true
					candidates = append(candidates, candidate)
				}
			}

			if !view.Stealth {
				direct := directCredentialIDs(view, node.ID)
				for _, credentialID := range orderedCredentialIDs(view, direct) {
					value := view.Credentials[credentialID]
					credential := view.Nodes[credentialID]
					if !credentialCompatibleWithService(credential, service) {
						continue
					}
					candidate := base
					candidate.Priority = 3
					if direct[credentialID] {
						candidate.Priority = 1
					}
					candidate.CredentialID = credentialID
					candidate.PathNodeIDs = []string{credentialID, node.ID}
					candidate.Inputs = cloneStringMap(base.Inputs)
					candidate.Inputs["credential"] = value
					valueHash, _ := credential.Properties["value_hash"].(string)
					candidate.Key = candidateKey(mod.ID(), endpoint, valueHash, "", view.Deep)
					if !seen[candidate.Key] {
						seen[candidate.Key] = true
						candidates = append(candidates, candidate)
					}
				}
			}

		}
	}
	return candidates
}

func (a serviceCollectAction) Execute(ctx context.Context, candidate Candidate, _ Journal) (Result, error) {
	defaultInventory := serviceInventoryOutcome(candidate, nil, ingest.OutcomeFailed, 0, "collection did not complete")
	mod, ok := module.Get(candidate.ModuleID)
	if !ok {
		return Result{InventoryOutcomes: []ingest.CollectionOutcome{defaultInventory}}, fmt.Errorf("service collector %q is not registered", candidate.ModuleID)
	}
	collector, ok := mod.(action.ServiceCollector)
	if !ok {
		return Result{InventoryOutcomes: []ingest.CollectionOutcome{defaultInventory}}, fmt.Errorf("module %q is not a service collector", candidate.ModuleID)
	}
	credentials := map[string]string{}
	extras := map[string]any{}
	value := candidate.Inputs["credential"]
	switch candidate.Inputs["service"] {
	case "litellm":
		credentials["master_key"] = value
	case "openwebui":
		credentials["api_key"] = value
		extras["api-key"] = value
	case "jupyter":
		credentials["token"] = value
	}
	if candidate.Inputs["deep"] == "true" {
		switch candidate.Inputs["service"] {
		case "qdrant":
			extras["include-points"] = true
			extras["points-per-collection"] = 100
			extras["max-total-resources"] = 5000
		case "ollama":
			extras["include-embeddings"] = true
		}
	}
	result, err := collector.Collect(ctx, candidate.Target, action.CollectOptions{
		Credentials: credentials, MaxItems: 1000, Timeout: a.timeout,
		Extras: extras,
	})
	if err != nil {
		defaultInventory.Error = err.Error()
		return Result{InventoryOutcomes: []ingest.CollectionOutcome{defaultInventory}}, err
	}
	if result == nil || result.IngestData == nil {
		err := fmt.Errorf("service collector %q returned no graph", candidate.ModuleID)
		defaultInventory.Error = err.Error()
		return Result{InventoryOutcomes: []ingest.CollectionOutcome{defaultInventory}}, err
	}
	inventoryState := ingest.OutcomeComplete
	inventoryItems := len(result.IngestData.Graph.Nodes)
	inventoryError := ""
	if result.Summary.PartialFailures > 0 || len(result.PartialErrors) > 0 {
		inventoryState = ingest.OutcomePartial
		inventoryError = strings.Join(result.PartialErrors, "; ")
	}
	if result.Inventory != nil {
		inventoryState = result.Inventory.State
		inventoryItems = result.Inventory.Items
		inventoryError = result.Inventory.Error
	}
	inventory := serviceInventoryOutcome(
		candidate,
		result.Inventory,
		inventoryState,
		inventoryItems,
		inventoryError,
	)
	graph := result.IngestData.Graph
	ingest.TagObservationDomain(&graph, inventory.CoverageKey)
	plannerResult := Result{
		Graph: graph, InventoryOutcomes: []ingest.CollectionOutcome{inventory},
		Outcome: "collection_observed",
	}
	if result.Summary.PartialFailures > 0 || len(result.PartialErrors) > 0 {
		plannerResult.Outcome = "collection_partial"
		return plannerResult, collectionPartialError(candidate.ModuleID, result)
	}
	return plannerResult, nil
}

func serviceInventoryOutcome(
	candidate Candidate,
	report *action.InventoryResult,
	state ingest.OutcomeState,
	items int,
	errorText string,
) ingest.CollectionOutcome {
	name := strings.TrimSpace(candidate.Inputs["inventory_name"])
	if name == "" {
		name = "inventory"
	}
	if report != nil && strings.TrimSpace(report.Name) != "" {
		name = strings.TrimSpace(report.Name)
	}
	serviceID := strings.TrimSpace(candidate.Inputs["node_id"])
	if serviceID == "" {
		serviceID = canonicalTarget(candidate.Target.Address)
	}
	key := ingest.CanonicalCoverageKey(
		"scan",
		"service_inventory",
		candidate.ModuleID+"\x00"+serviceID+"\x00"+name,
	)
	return ingest.CollectionOutcome{
		Collector: "scan", CoverageKey: key,
		ParentCoverageKey: ingest.CollectorRootCoverageKey("scan"),
		Target:            serviceID, Method: "service_inventory:" + name,
		State: state, Items: items, Error: errorText,
	}
}

// ollamaEmbeddingAction is deliberately separate from ordinary Ollama
// inventory: it invokes bounded model compute and therefore exists only in
// deep active scans.
type ollamaEmbeddingAction struct {
	timeout time.Duration
}

func (ollamaEmbeddingAction) ID() string { return "ollama.embedding.invoke" }

func (a ollamaEmbeddingAction) Candidates(view View) []Candidate {
	if !view.Deep || view.Stealth {
		return nil
	}
	mod, ok := module.GetByTarget("ollama", action.Collect)
	if !ok {
		return nil
	}
	var candidates []Candidate
	for _, node := range view.ByKind["OllamaInstance"] {
		endpoint := stringProperty(node.Properties, "endpoint")
		if endpoint == "" {
			continue
		}
		candidates = append(candidates, Candidate{
			Key: candidateKey(a.ID(), endpoint, "", node.ID, true), Priority: 6,
			ModuleID: mod.ID(), ResourceID: node.ID,
			Target: action.Target{Kind: "url", Address: endpoint, Meta: map[string]string{
				"url": endpoint, "node_id": node.ID, "service_kind": "ollama",
			}},
			PathNodeIDs: []string{node.ID},
			Inputs: map[string]string{
				"service": "ollama", "node_id": node.ID, "deep": "true",
				"observation_domains": strings.Join(node.ObservationDomains, "\x1f"),
			},
		})
	}
	return candidates
}

func (a ollamaEmbeddingAction) Execute(ctx context.Context, candidate Candidate, journal Journal) (Result, error) {
	result, err := serviceCollectAction(a).Execute(ctx, candidate, journal)
	if err != nil {
		return result, err
	}
	for _, node := range result.Graph.Nodes {
		if containsPlannerString(node.Kinds, "OllamaInstance") &&
			node.Properties["embedding_capability_confirmed"] == true {
			result.Outcome = "embedding_compute_observed"
			return result, nil
		}
	}
	result.Outcome = "embedding_compute_not_confirmed"
	return result, errors.New("ollama embedding probe did not confirm compute access")
}

func credentialCompatibleWithService(node ingest.Node, service string) bool {
	methods := credentialPropertyValues(node.Properties, "auth_method", "auth_methods")
	if len(methods) > 0 {
		supported := false
		for _, method := range methods {
			if common.AuthMethod(method) == common.AuthBearer || common.AuthMethod(method) == common.AuthAPIKey {
				supported = true
				break
			}
		}
		if !supported {
			return false
		}
	}
	hints := append([]string(nil), methods...)
	for _, field := range [][2]string{{"type", "types"}, {"name", "names"}, {"format", "formats"}} {
		hints = append(hints, credentialPropertyValues(node.Properties, field[0], field[1])...)
	}
	joined := strings.ToLower(strings.Join(hints, " "))
	switch service {
	case "litellm":
		return strings.Contains(joined, "master") || strings.Contains(joined, "bearer") || strings.Contains(joined, "api")
	case "openwebui", "jupyter":
		return strings.Contains(joined, "bearer") || strings.Contains(joined, "token") ||
			strings.Contains(joined, "api") || strings.Contains(joined, "jwt")
	default:
		return false
	}
}

type a2aCredentialAction struct {
	insecure bool
	timeout  time.Duration
}

func (a2aCredentialAction) ID() string { return "a2a.credential.collect" }

func (a a2aCredentialAction) Candidates(view View) []Candidate {
	if view.Stealth {
		return nil
	}
	var candidates []Candidate
	seen := make(map[string]bool)
	for _, agent := range view.ByKind["A2AAgent"] {
		// This action only refetches the Agent Card with a bearer. When the
		// initial card fetch and the bounded protocol probe both succeeded
		// anonymously, another card fetch cannot prove that the bearer was
		// accepted or expand the collected surface.
		if stringProperty(agent.Properties, "auth_probe_status") ==
			a2acollector.A2AAuthProbeStatusAnonymousProtocolAccess {
			continue
		}
		endpoint := stringProperty(agent.Properties, "url")
		if endpoint == "" {
			continue
		}
		direct := directCredentialIDs(view, agent.ID)
		for _, credentialID := range orderedCredentialIDs(view, direct) {
			raw := view.Credentials[credentialID]
			credential := view.Nodes[credentialID]
			if !bearerCredential(credential) {
				continue
			}
			material := normalizeBearer(raw)
			if material == "" {
				continue
			}
			valueHash := stringProperty(credential.Properties, "value_hash")
			key := candidateKey(a.ID(), endpoint, valueHash, agent.ID, view.Deep)
			if seen[key] {
				continue
			}
			seen[key] = true
			priority := 3
			if direct[credentialID] {
				priority = 1
			}
			candidates = append(candidates, Candidate{
				Key: key, Priority: priority, ModuleID: a.ID(), CredentialID: credentialID,
				Target: action.Target{Kind: "url", Address: endpoint, Meta: map[string]string{
					"url": endpoint, "node_id": agent.ID,
				}},
				PathNodeIDs: []string{credentialID, agent.ID},
				Inputs: map[string]string{
					"credential":          material,
					"observation_domains": strings.Join(agent.ObservationDomains, "\x1f"),
				},
			})
		}
	}
	return candidates
}

func (a a2aCredentialAction) Execute(ctx context.Context, candidate Candidate, _ Journal) (Result, error) {
	collector := a2acollector.NewA2ACollector(
		a2acollector.WithConcurrency(1),
		a2acollector.WithTimeout(a.timeout),
		a2acollector.WithInsecure(a.insecure),
	)
	data, err := collector.Collect(ctx, icollector.CollectOptions{
		TargetURL: candidate.Target.Address, AuthToken: candidate.Inputs["credential"],
		Timeout: a.timeout, Insecure: a.insecure, ScanID: candidate.Inputs["scan_id"],
	})
	if err != nil {
		return Result{}, err
	}
	if data == nil {
		return Result{}, fmt.Errorf("A2A collector returned no graph")
	}
	if err := requireSuccessfulA2ACollection(data.Meta.Collection); err != nil {
		return Result{Graph: data.Graph, Outcome: "authenticated_agent_card_failed"}, err
	}
	domains := splitNonEmpty(candidate.Inputs["observation_domains"], "\x1f")
	if len(domains) == 0 {
		domains = []string{ingest.CollectorRootCoverageKey("scan")}
	}
	// This is an enrichment of the already admitted A2A observation. Keep its
	// ownership on the enclosing scan domains; the planner does not publish a
	// second independent collection envelope.
	for index := range data.Graph.Nodes {
		data.Graph.Nodes[index].ObservationDomains = append([]string(nil), domains...)
	}
	for index := range data.Graph.Edges {
		data.Graph.Edges[index].ObservationDomains = append([]string(nil), domains...)
	}
	return Result{Graph: data.Graph, Outcome: "authenticated_agent_card_observed"}, nil
}

func collectionPartialError(moduleID string, result *action.CollectResult) error {
	count := result.Summary.PartialFailures
	if count < len(result.PartialErrors) {
		count = len(result.PartialErrors)
	}
	details := strings.Join(result.PartialErrors, "; ")
	if details == "" {
		details = "collector reported incomplete results"
	}
	return fmt.Errorf("service collector %q had %d partial failure(s): %s", moduleID, count, details)
}

func requireSuccessfulA2ACollection(report *ingest.CollectionReport) error {
	if report == nil || len(report.Outcomes) == 0 {
		return errors.New("A2A collector returned no target outcome")
	}
	var failures []string
	for _, outcome := range report.Outcomes {
		if outcome.State == ingest.OutcomeComplete {
			return nil
		}
		if outcome.Error != "" {
			failures = append(failures, outcome.Error)
		}
	}
	if len(failures) == 0 {
		return fmt.Errorf("A2A collection completed with state %q", report.State)
	}
	return fmt.Errorf("A2A collection failed: %s", strings.Join(failures, "; "))
}

type credentialReachAction struct {
	insecure bool
	timeout  time.Duration
}

func (credentialReachAction) ID() string { return "credential_reach" }

func (a credentialReachAction) Candidates(view View) []Candidate {
	if view.Stealth {
		return nil
	}
	var candidates []Candidate
	seen := make(map[string]bool)
	for _, server := range view.ByKind["MCPServer"] {
		endpoint := stringProperty(server.Properties, "endpoint")
		if endpoint == "" || stringProperty(server.Properties, "transport") != "http" {
			continue
		}
		resources := targetsForEdge(view.Outgoing[server.ID], "PROVIDES_RESOURCE")
		if len(resources) == 0 {
			continue
		}
		publicResources := make(map[string]bool)
		for _, resourceID := range targetsForEdge(view.Outgoing[server.ID], "PUBLIC_ACCESS_OBSERVED") {
			publicResources[resourceID] = true
		}
		direct := directCredentialIDs(view, server.ID)
		for _, credentialID := range orderedCredentialIDs(view, direct) {
			value := view.Credentials[credentialID]
			credential := view.Nodes[credentialID]
			if !bearerCredential(credential) {
				continue
			}
			material := strings.TrimSpace(value)
			if strings.HasPrefix(strings.ToLower(material), "bearer ") {
				material = strings.TrimSpace(material[len("bearer "):])
			}
			if material == "" {
				continue
			}
			for _, resourceID := range resources {
				// Once the anonymous control has proved this resource public,
				// trying more credentials cannot establish credential-gated reach.
				if publicResources[resourceID] {
					continue
				}
				resource, ok := view.Nodes[resourceID]
				if !ok {
					continue
				}
				uri := stringProperty(resource.Properties, "uri")
				if uri == "" {
					continue
				}
				valueHash := stringProperty(credential.Properties, "value_hash")
				candidate := Candidate{
					Priority: 4, ModuleID: a.ID(), CredentialID: credentialID,
					ResourceID: resourceID,
					Target: action.Target{Kind: "url", Address: endpoint, Meta: map[string]string{
						"url": endpoint, "node_id": server.ID,
					}},
					PathNodeIDs: []string{server.ID, credentialID, resourceID},
					Inputs: map[string]string{
						"credential": material, "resource_uri": uri, "server_id": server.ID,
						"resource_domains": strings.Join(resource.ObservationDomains, "\x1f"),
					},
				}
				if direct[credentialID] {
					candidate.Priority = 4
				}
				candidate.Key = candidateKey(a.ID(), endpoint, valueHash, resourceID, view.Deep)
				if seen[candidate.Key] {
					continue
				}
				seen[candidate.Key] = true
				candidates = append(candidates, candidate)
			}
		}
	}
	return candidates
}

func (a credentialReachAction) Execute(ctx context.Context, candidate Candidate, _ Journal) (Result, error) {
	proof := credreach.VerifyAccess(
		ctx, candidate.Target.Address, candidate.Inputs["resource_uri"],
		candidate.Inputs["credential"], a.insecure, a.timeout,
	)
	actionID := candidate.Inputs["action_id"]
	if actionID == "" {
		actionID = common.HashSHA256(candidate.Key)
	}
	domains := splitNonEmpty(candidate.Inputs["resource_domains"], "\x1f")
	referenceNodes := []ingest.Node{
		{ID: candidate.CredentialID, Kinds: []string{"Credential"}, Properties: map[string]any{}, PropertySemantics: ingest.NodePropertySemanticsReferenceOnly, ObservationDomains: domains},
		{ID: candidate.ResourceID, Kinds: []string{"MCPResource"}, Properties: map[string]any{}, PropertySemantics: ingest.NodePropertySemanticsReferenceOnly, ObservationDomains: domains},
	}
	if len(proof.Content) > 0 {
		referenceNodes[1].PropertySemantics = ""
		referenceNodes[1].Properties["observed_content"] = string(proof.Content)
		referenceNodes[1].Properties["observed_content_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	graph := ingest.GraphData{Nodes: referenceNodes, Edges: []ingest.Edge{}}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	switch proof.Outcome {
	case credreach.OutcomeCredentialGatedReachVerified:
		properties := map[string]any{
			"scan_id": candidate.Inputs["scan_id"], "is_composite": false,
			"confidence": 1.0, "risk_weight": 0.1,
			"action_id": actionID, "action": "credential_reach", "verified_at": now,
			"proof_type": "differential_resource_read", "outcome": "credential_required",
			"control_stage": string(proof.Control.Stage), "control_status": string(proof.Control.Status),
			"control_resource_addressed": proof.Control.ResourceAddressed,
			"credential_stage":           string(proof.Credential.Stage), "credential_status": string(proof.Credential.Status),
			"credential_resource_addressed": proof.Credential.ResourceAddressed,
			"cleanup_status":                "not_applicable",
		}
		graph.Edges = append(graph.Edges, ingest.Edge{
			Source: candidate.CredentialID, Target: candidate.ResourceID,
			Kind: "CREDENTIAL_ACCESS_OBSERVED", SourceKind: "Credential", TargetKind: "MCPResource",
			Properties: properties, ObservationDomains: domains,
		})
	case credreach.OutcomeAnonymousAccessObserved, credreach.OutcomeAnonymousAccessCredentialRejected:
		serverID := candidate.Inputs["server_id"]
		graph.Nodes = append(graph.Nodes, ingest.Node{
			ID: serverID, Kinds: []string{"MCPServer"}, Properties: map[string]any{},
			PropertySemantics: ingest.NodePropertySemanticsReferenceOnly, ObservationDomains: domains,
		})
		properties := common.NewEdgeProps(candidate.Inputs["scan_id"], 1.0, 0.1)
		properties["action_id"] = actionID
		properties["action"] = "credential_reach"
		properties["observed_at"] = now
		properties["outcome"] = string(proof.Outcome)
		graph.Edges = append(graph.Edges, ingest.Edge{
			Source: serverID, Target: candidate.ResourceID, Kind: "PUBLIC_ACCESS_OBSERVED",
			SourceKind: "MCPServer", TargetKind: "MCPResource", Properties: properties,
			ObservationDomains: domains,
		})
	}
	return Result{Graph: graph, Outcome: string(proof.Outcome)}, nil
}

func directCredentialIDs(view View, serverID string) map[string]bool {
	direct := make(map[string]bool)
	for _, edge := range view.Outgoing[serverID] {
		if edge.Kind != "AUTHENTICATES_WITH" {
			continue
		}
		for _, identityEdge := range view.Outgoing[edge.Target] {
			if identityEdge.Kind == "USES_CREDENTIAL" {
				direct[identityEdge.Target] = true
			}
		}
	}
	return direct
}

func targetsForEdge(edges []ingest.Edge, kind string) []string {
	seen := make(map[string]bool)
	var targets []string
	for _, edge := range edges {
		if edge.Kind == kind && !seen[edge.Target] {
			seen[edge.Target] = true
			targets = append(targets, edge.Target)
		}
	}
	sort.Strings(targets)
	return targets
}

func bearerCredential(node ingest.Node) bool {
	for _, method := range credentialPropertyValues(node.Properties, "auth_method", "auth_methods") {
		if common.AuthMethod(method) == common.AuthBearer {
			return true
		}
	}
	return false
}

func credentialPropertyValues(properties map[string]any, singular, plural string) []string {
	seen := make(map[string]bool)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = true
		}
	}
	if value, ok := properties[singular].(string); ok {
		add(value)
	}
	switch values := properties[plural].(type) {
	case []string:
		for _, value := range values {
			add(value)
		}
	case []any:
		for _, raw := range values {
			if value, ok := raw.(string); ok {
				add(value)
			}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func stringProperty(properties map[string]any, key string) string {
	value, _ := properties[key].(string)
	return strings.TrimSpace(value)
}

func cloneStringMap(values map[string]string) map[string]string {
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

func splitNonEmpty(value, separator string) []string {
	if value == "" {
		return []string{}
	}
	return uniqueStrings(strings.Split(value, separator))
}

func recoveryData(value any) map[string]any {
	document, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	var data map[string]any
	if json.Unmarshal(document, &data) != nil {
		return map[string]any{}
	}
	return data
}
