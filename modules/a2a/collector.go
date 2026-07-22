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

type a2aCardResult struct {
	card *AgentCardData
	url  string
	err  error
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

	results := make([]a2aCardResult, len(targets))
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
				results[idx] = a2aCardResult{url: tgt, err: err}
				return
			}
			card, err := ParseAgentCard(ctx, raw, engine, verifyOpts)
			if err != nil {
				results[idx] = a2aCardResult{url: tgt, err: err}
				return
			}
			if card.URL == "" {
				card.URL = normalizeBaseURL(tgt)
			}

			results[idx] = a2aCardResult{card: card, url: tgt}
		}(i, target)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		leftScope := a2aCoverageKey(results[i].url)
		rightScope := a2aCoverageKey(results[j].url)
		if leftScope == rightScope {
			return results[i].url < results[j].url
		}
		return leftScope < rightScope
	})
	applyA2AAuthProbes(ctx, results, insecure, c.timeout, c.concurrency)

	data := common.NewIngestData("a2a", scanID)
	data.Meta.Ruleset = rules.ManifestForEngine(engine)
	nodeSeen := make(map[string]bool)
	addNode := func(node ingest.Node) {
		if key, comparable := a2aNodeContributionDedupKey(node); comparable && nodeSeen[key] {
			return
		} else if comparable {
			nodeSeen[key] = true
		}
		data.Graph.Nodes = append(data.Graph.Nodes, node)
	}
	edgeSeen := make(map[string]bool)
	addEdge := func(edge ingest.Edge) {
		if key, comparable := a2aEdgeContributionDedupKey(edge); comparable && edgeSeen[key] {
			return
		} else if comparable {
			edgeSeen[key] = true
		}
		data.Graph.Edges = append(data.Graph.Edges, edge)
	}
	report := &ingest.CollectionReport{}

	var allCards []*AgentCardData
	coverage := make(map[string]bool, len(results))
	agentScopes := make(map[string][]string, len(results))

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
		agentID := agentNodeID(r.card)
		agentScopes[agentID] = ingest.MergeObservationDomains(
			agentScopes[agentID],
			[]string{scopeKey},
		)
		nodes, edges := buildGraph(r.card, scanID)
		graph := ingest.GraphData{Nodes: nodes, Edges: edges}
		ingest.TagObservationDomain(&graph, scopeKey)
		for _, n := range graph.Nodes {
			addNode(n)
		}
		for _, edge := range graph.Edges {
			addEdge(edge)
		}
	}

	delegations := DetectDelegation(allCards)
	delegationSeen := make(map[DelegationEdge]bool, len(delegations))
	for _, d := range delegations {
		if d.SourceAgentID == d.TargetAgentID {
			continue
		}
		if delegationSeen[d] {
			continue
		}
		delegationSeen[d] = true
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
		addEdge(edge)
	}

	authDomains := DetectSameAuthDomain(allCards)
	authDomainSeen := make(map[string]bool, len(authDomains))
	for _, ad := range authDomains {
		if ad.AgentID1 == ad.AgentID2 {
			continue
		}
		sourceAgentID, targetAgentID := ad.AgentID1, ad.AgentID2
		if sourceAgentID > targetAgentID {
			sourceAgentID, targetAgentID = targetAgentID, sourceAgentID
		}
		relationKey := sourceAgentID + "\x00" + targetAgentID
		if authDomainSeen[relationKey] {
			continue
		}
		authDomainSeen[relationKey] = true
		props := common.NewEdgeProps(scanID, 0.9, 0.0)
		edge := common.NewEdge(sourceAgentID, targetAgentID, "SAME_AUTH_DOMAIN", "A2AAgent", "A2AAgent", props)
		setRelationObservationScopes(
			&edge,
			agentScopes[sourceAgentID],
			agentScopes[targetAgentID],
		)
		addEdge(edge)
	}
	for key := range coverage {
		report.CoverageKeys = append(report.CoverageKeys, key)
	}
	sort.Strings(report.CoverageKeys)
	report.State = ingest.AggregateOutcomeState(report.Outcomes)
	data.Meta.Collection = report

	return data, nil
}

func a2aNodeContributionKey(node ingest.Node) string {
	return node.ID + "\x00" + string(node.PropertySemantics) + "\x00" +
		strings.Join(ingest.MergeObservationDomains(node.ObservationDomains), "\x1f")
}

func a2aEdgeContributionKey(edge ingest.Edge) string {
	return edge.Source + "\x00" + edge.Kind + "\x00" + edge.Target + "\x00" +
		string(edge.ObservationSemantics) + "\x00" +
		strings.Join(ingest.MergeObservationDomains(edge.ObservationDomains), "\x1f")
}

func a2aNodeContributionDedupKey(node ingest.Node) (string, bool) {
	digest, err := common.CanonicalJSONHash(node)
	return a2aNodeContributionKey(node) + "\x00" + digest, err == nil
}

func a2aEdgeContributionDedupKey(edge ingest.Edge) (string, bool) {
	digest, err := common.CanonicalJSONHash(edge)
	return a2aEdgeContributionKey(edge) + "\x00" + digest, err == nil
}

func setRelationObservationScopes(
	edge *ingest.Edge,
	sourceScopes, targetScopes []string,
) {
	// A derived relation is one logical fact, so all currently successful aliases
	// for both endpoints form one indivisible dependency group. A subsequent
	// partial collection omits failed aliases from its fresh affirmative group;
	// the writer can then atomically replace the old group when every remaining
	// dependency completed, without selecting an arbitrary canonical alias.
	edge.ObservationDomains = ingest.MergeObservationDomains(
		sourceScopes,
		targetScopes,
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
	applyAuthProbeProperties(agentProps, card.AuthProbe)

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
