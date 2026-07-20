package a2a

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
	jose "github.com/go-jose/go-jose/v4"
)

type A2ACollector struct {
	concurrency      int
	timeout          time.Duration
	insecure         bool
	jwksFetchEnabled bool
	trustedKeysPath  string
	trustedKeys      *jose.JSONWebKeySet
}

type Option func(*A2ACollector)

func WithConcurrency(n int) Option {
	return func(c *A2ACollector) { c.concurrency = n }
}

func WithTimeout(d time.Duration) Option {
	return func(c *A2ACollector) { c.timeout = d }
}

func WithInsecure(v bool) Option {
	return func(c *A2ACollector) { c.insecure = v }
}

// WithJWKSFetch toggles spec-compliant remote JWKS (`jku`) resolution during
// signature verification. Enabled by default; disable for a fully offline scan.
func WithJWKSFetch(v bool) Option {
	return func(c *A2ACollector) { c.jwksFetchEnabled = v }
}

// WithTrustedKeysFile points at a JWKS JSON file whose keys are used as an
// out-of-band trusted key store for signature verification (the A2A spec's
// trusted-key-store option), consulted before any network fetch.
func WithTrustedKeysFile(path string) Option {
	return func(c *A2ACollector) { c.trustedKeysPath = path }
}

func NewA2ACollector(opts ...Option) *A2ACollector {
	c := &A2ACollector{
		concurrency:      5,
		timeout:          15 * time.Second,
		jwksFetchEnabled: true,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *A2ACollector) Name() string { return "a2a" }

func (c *A2ACollector) Collect(ctx context.Context, opts collector.CollectOptions) (*ingest.IngestData, error) {
	targets, err := buildTargetList(opts)
	if err != nil {
		return nil, fmt.Errorf("build target list: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets specified: provide --target, --targets, or --targets-file")
	}

	engine := opts.RulesEngine
	if engine == nil {
		var engineErr error
		engine, engineErr = rules.NewEngine(rules.LoadOptions{})
		if engineErr != nil {
			return nil, fmt.Errorf("rules engine: %w", engineErr)
		}
	}

	scanID := opts.ScanID
	if scanID == "" {
		scanID = common.GenerateScanID("a2a")
	}

	insecure := opts.Insecure || c.insecure
	authToken := opts.AuthToken

	if c.trustedKeysPath != "" && c.trustedKeys == nil {
		set, err := LoadJWKSFile(c.trustedKeysPath)
		if err != nil {
			return nil, fmt.Errorf("load a2a trusted keys %s: %w", c.trustedKeysPath, err)
		}
		c.trustedKeys = set
	}

	verifyOpts := VerifyOptions{TrustedKeys: c.trustedKeys}
	if c.jwksFetchEnabled {
		verifyOpts.Fetcher = NewJWKSFetcher(c.timeout)
	}

	type cardResult struct {
		card *AgentCardData
		url  string
		err  error
	}

	results := make([]cardResult, len(targets))
	sem := make(chan struct{}, c.concurrency)
	var wg sync.WaitGroup

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			raw, err := FetchAgentCard(ctx, tgt, authToken, insecure, c.timeout)
			if err != nil {
				results[idx] = cardResult{url: tgt, err: err}
				return
			}
			card, err := ParseAgentCard(ctx, raw, engine, verifyOpts)
			if err != nil {
				results[idx] = cardResult{url: tgt, err: err}
				return
			}
			if card.URL == "" {
				card.URL = normalizeBaseURL(tgt)
			}

			results[idx] = cardResult{card: card, url: tgt}
		}(i, target)
	}
	wg.Wait()

	data := common.NewIngestData("a2a", scanID)
	data.Meta.Origin = opts.Origin
	data.Meta.Ruleset = rules.ManifestForEngine(engine)
	nodeIndex := make(map[string]int)
	addNode := func(node ingest.Node) {
		if index, ok := nodeIndex[node.ID]; ok {
			data.Graph.Nodes[index].ObservationDomains = ingest.MergeObservationDomains(
				data.Graph.Nodes[index].ObservationDomains,
				node.ObservationDomains,
			)
			if data.Graph.Nodes[index].Properties == nil {
				data.Graph.Nodes[index].Properties = make(map[string]any)
			}
			for key, value := range node.Properties {
				data.Graph.Nodes[index].Properties[key] = value
			}
			return
		}
		nodeIndex[node.ID] = len(data.Graph.Nodes)
		data.Graph.Nodes = append(data.Graph.Nodes, node)
	}
	report := &ingest.CollectionReport{}

	var allCards []*AgentCardData
	coverage := make(map[string]bool, len(results))
	agentScopes := make(map[string]string, len(results))

	for _, r := range results {
		scopeKey := a2aCoverageKey(r.url)
		coverage[scopeKey] = true
		if r.err != nil {
			log.Printf("[a2a] warning: failed to collect %s: %v", r.url, r.err)
			report.Outcomes = append(report.Outcomes, ingest.CollectionOutcome{
				Collector:   "a2a",
				CoverageKey: scopeKey,
				Target:      r.url,
				Method:      "agent_card",
				State:       ingest.OutcomeFailed,
				Error:       r.err.Error(),
			})
			continue
		}
		report.Outcomes = append(report.Outcomes, ingest.CollectionOutcome{
			Collector:   "a2a",
			CoverageKey: scopeKey,
			Target:      r.url,
			Method:      "agent_card",
			State:       ingest.OutcomeComplete,
			Items:       1,
		})
		allCards = append(allCards, r.card)
		agentScopes[agentNodeID(r.card)] = scopeKey
		nodes, edges := buildGraph(r.card, scanID)
		graph := ingest.GraphData{Nodes: nodes, Edges: edges}
		ingest.TagObservationDomain(&graph, scopeKey)
		for _, n := range graph.Nodes {
			addNode(n)
		}
		data.Graph.Edges = append(data.Graph.Edges, graph.Edges...)
	}

	delegations := DetectDelegation(allCards)
	for _, d := range delegations {
		if d.SourceAgentID == d.TargetAgentID {
			continue
		}
		riskWeight := 0.1
		if hasAuth(allCards, d.TargetAgentID) {
			riskWeight = 0.5
		}
		props := common.NewEdgeProps(scanID, d.Confidence, riskWeight)
		props["evidence_state"] = d.EvidenceState
		props["match_type"] = d.MatchType
		props["match_field"] = d.MatchField
		props["matched_reference"] = d.MatchedRef
		edge := common.NewEdge(d.SourceAgentID, d.TargetAgentID, "DELEGATES_TO", "A2AAgent", "A2AAgent", props)
		setRelationObservationScopes(
			&edge,
			agentScopes[d.SourceAgentID],
			agentScopes[d.TargetAgentID],
		)
		data.Graph.Edges = append(data.Graph.Edges, edge)
	}

	authDomains := DetectSameAuthDomain(allCards)
	for _, ad := range authDomains {
		if ad.AgentID1 == ad.AgentID2 {
			continue
		}
		props := common.NewEdgeProps(scanID, 0.9, 0.0)
		edge := common.NewEdge(ad.AgentID1, ad.AgentID2, "SAME_AUTH_DOMAIN", "A2AAgent", "A2AAgent", props)
		setRelationObservationScopes(
			&edge,
			agentScopes[ad.AgentID1],
			agentScopes[ad.AgentID2],
		)
		data.Graph.Edges = append(data.Graph.Edges, edge)
	}
	for key := range coverage {
		report.CoverageKeys = append(report.CoverageKeys, key)
	}
	sort.Strings(report.CoverageKeys)
	report.State = ingest.AggregateOutcomeState(report.Outcomes)
	data.Meta.Collection = report

	return data, nil
}

func setRelationObservationScopes(edge *ingest.Edge, sourceScope, targetScope string) {
	edge.ObservationDomains = ingest.MergeObservationDomains(
		[]string{sourceScope},
		[]string{targetScope},
	)
	if len(edge.ObservationDomains) >= 2 {
		edge.ObservationSemantics = ingest.ObservationSemanticsAllDependencies
		return
	}
	edge.ObservationSemantics = ingest.ObservationSemanticsAnyOwner
}

func a2aCoverageKey(target string) string {
	return ingest.CanonicalCoverageKey(
		"a2a",
		"target",
		ingest.CanonicalURLScope(normalizeBaseURL(target)),
	)
}

func buildTargetList(opts collector.CollectOptions) ([]string, error) {
	var targets []string

	if opts.TargetURL != "" {
		targets = append(targets, opts.TargetURL)
	}
	targets = append(targets, opts.TargetURLs...)

	if opts.TargetURLsFile != "" {
		lines, err := readURLsFile(opts.TargetURLsFile)
		if err != nil {
			return nil, fmt.Errorf("read targets file %s: %w", opts.TargetURLsFile, err)
		}
		targets = append(targets, lines...)
	}

	seen := make(map[string]bool)
	var deduped []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		normalized := normalizeBaseURL(t)
		if !seen[normalized] {
			seen[normalized] = true
			deduped = append(deduped, t)
		}
	}
	return deduped, nil
}

func readURLsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	return urls, scanner.Err()
}

func buildGraph(card *AgentCardData, scanID string) ([]ingest.Node, []ingest.Edge) {
	var nodes []ingest.Node
	var edges []ingest.Edge

	agentID := agentNodeID(card)
	authAssessment := common.AssessAuth(card.AuthMethod)
	signatureStatus := card.SignatureStatus
	if signatureStatus == "" {
		signatureStatus = "unknown"
	}
	signatureKeySource := card.SignatureKeySource
	if signatureKeySource == "" {
		signatureKeySource = SigKeySourceNone
	}
	signatureKeyTrust := card.SignatureKeyTrust
	if signatureKeyTrust == "" {
		signatureKeyTrust = SigKeyTrustUnknown
	}
	authEvidence := common.AuthEvidenceUnknown
	if len(card.SecurityRequirements) > 0 && card.SecurityValid {
		authEvidence = common.AuthEvidenceDeclaredScheme
	} else if len(card.SecuritySchemes) > 0 {
		authEvidence = common.AuthEvidenceDeclaredScheme
	}

	agentProps := map[string]any{
		"name":                          card.Name,
		"description":                   card.Description,
		"url":                           card.URL,
		"provider":                      card.Provider,
		"version":                       card.Version,
		"card_schema_version":           card.SchemaVersion,
		"card_present_fields":           card.PresentFields,
		"card_conformant":               card.Conformant,
		"card_conformance_errors":       card.ConformanceErrors,
		"protocol_versions":             card.ProtocolVersions,
		"capabilities":                  card.Capabilities,
		"auth_method":                   string(authAssessment.Method),
		"auth_assurance":                string(authAssessment.Assurance),
		"auth_evidence":                 authEvidence,
		"is_signed":                     card.IsSigned,
		"signature_verification_status": signatureStatus,
		"signature_key_source":          signatureKeySource,
		"signature_key_trust":           signatureKeyTrust,
		"is_https":                      card.IsHTTPS,
		"card_hash":                     card.CardHash,
		"collection_state":              string(ingest.OutcomeComplete),
	}
	interfacesData := make([]map[string]any, len(card.Interfaces))
	for index, iface := range card.Interfaces {
		interfacesData[index] = map[string]any{
			"url":              iface.URL,
			"protocol_binding": iface.ProtocolBinding,
			"protocol_version": iface.ProtocolVersion,
			"tenant":           iface.Tenant,
			"preferred":        iface.Preferred,
			"conformant":       iface.Conformant,
		}
	}
	agentProps["interfaces"] = interfacesData

	schemesData := make([]map[string]any, len(card.SecuritySchemes))
	for i, s := range card.SecuritySchemes {
		schemesData[i] = map[string]any{
			"name":       s.Name,
			"type":       s.Type,
			"scheme":     s.Scheme,
			"conformant": s.Conformant,
		}
	}
	agentProps["security_schemes"] = schemesData
	agentProps["security_requirements"] = securityRequirementsProperty(card.SecurityRequirements)

	nodes = append(nodes, common.NewNode(agentID, []string{"A2AAgent"}, agentProps))

	for _, skill := range card.Skills {
		if skill.ID == "" {
			continue
		}
		skillID := ingest.ComputeNodeID("A2ASkill", agentID, skill.ID)
		skillProps := map[string]any{
			"id":                     skill.ID,
			"name":                   skill.Name,
			"description":            skill.Description,
			"input_modes":            skill.InputModes,
			"output_modes":           skill.OutputModes,
			"description_hash":       skill.DescriptionHash,
			"has_injection_patterns": skill.HasInjection,
			"conformant":             skill.Conformant,
			"conformance_errors":     skill.ConformanceErrors,
			"security_requirements":  securityRequirementsProperty(skill.SecurityRequirements),
		}
		nodes = append(nodes, common.NewNode(skillID, []string{"A2ASkill"}, skillProps))

		if skill.Conformant {
			edgeProps := common.NewEdgeProps(scanID, 1.0, 0.1)
			edges = append(edges, common.NewEdge(agentID, skillID, "ADVERTISES_SKILL", "A2AAgent", "A2ASkill", edgeProps))
		}
	}

	if card.PreferredURLValid {
		hostInfo := common.ClassifyHost(card.URL)
		hostname := hostInfo.Hostname
		if hostname == "" {
			hostname = hostInfo.IP
		}
		if hostname != "" {
			hostID := common.HostNodeID(hostname)
			hostProps := map[string]any{
				"hostname": hostInfo.Hostname,
				"ip":       hostInfo.IP,
				"scope":    hostInfo.Scope,
			}
			nodes = append(nodes, common.NewNode(hostID, []string{"Host"}, hostProps))

			edgeProps := common.NewEdgeProps(scanID, 1.0, 0.0)
			edges = append(edges, common.NewEdge(agentID, hostID, "RUNS_ON", "A2AAgent", "Host", edgeProps))
		}
	}

	if card.SecurityValid && common.IsExplicitlyAuthenticated(card.AuthMethod) {
		identityID := ingest.ComputeNodeID("Identity", agentID, card.AuthMethod)
		identityProps := map[string]any{
			"type":           card.AuthMethod,
			"is_static":      card.AuthMethod == "apiKey",
			"auth_assurance": string(authAssessment.Assurance),
		}
		nodes = append(nodes, common.NewNode(identityID, []string{"Identity"}, identityProps))

		edgeProps := common.NewEdgeProps(scanID, 1.0, 0.0)
		edges = append(edges, common.NewEdge(agentID, identityID, "AUTHENTICATES_WITH", "A2AAgent", "Identity", edgeProps))
	}

	return nodes, edges
}

func securityRequirementsProperty(
	requirements []SecurityRequirement,
) []map[string]any {
	result := make([]map[string]any, len(requirements))
	for index, requirement := range requirements {
		schemes := make([]map[string]any, len(requirement.Schemes))
		for schemeIndex, scheme := range requirement.Schemes {
			schemes[schemeIndex] = map[string]any{
				"name":   scheme.Name,
				"scopes": scheme.Scopes,
			}
		}
		result[index] = map[string]any{
			"schemes":    schemes,
			"conformant": requirement.Conformant,
		}
	}
	return result
}

func agentNodeID(card *AgentCardData) string {
	return ingest.ComputeNodeID("A2AAgent", normalizeBaseURL(card.URL))
}

func hasAuth(cards []*AgentCardData, agentID string) bool {
	for _, c := range cards {
		if agentNodeID(c) == agentID && common.IsExplicitlyAuthenticated(c.AuthMethod) {
			return true
		}
	}
	return false
}
