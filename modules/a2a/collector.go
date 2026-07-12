package a2a

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
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
		verifyOpts.Fetcher = NewJWKSFetcher(insecure, c.timeout)
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
			raw.URL = tgt

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
	nodeIndex := make(map[string]bool)

	var allCards []*AgentCardData

	for _, r := range results {
		if r.err != nil {
			log.Printf("[a2a] warning: failed to collect %s: %v", r.url, r.err)
			continue
		}
		allCards = append(allCards, r.card)
		nodes, edges := buildGraph(r.card, scanID)
		for _, n := range nodes {
			if !nodeIndex[n.ID] {
				data.Graph.Nodes = append(data.Graph.Nodes, n)
				nodeIndex[n.ID] = true
			}
		}
		data.Graph.Edges = append(data.Graph.Edges, edges...)
	}

	delegations := DetectDelegation(allCards)
	for _, d := range delegations {
		riskWeight := 0.1
		if hasAuth(allCards, d.TargetAgentID) {
			riskWeight = 0.5
		}
		props := common.NewEdgeProps(scanID, d.Confidence, riskWeight)
		data.Graph.Edges = append(data.Graph.Edges,
			common.NewEdge(d.SourceAgentID, d.TargetAgentID, "DELEGATES_TO", "A2AAgent", "A2AAgent", props))
	}

	authDomains := DetectSameAuthDomain(allCards)
	for _, ad := range authDomains {
		props := common.NewEdgeProps(scanID, 0.9, 0.0)
		data.Graph.Edges = append(data.Graph.Edges,
			common.NewEdge(ad.AgentID1, ad.AgentID2, "SAME_AUTH_DOMAIN", "A2AAgent", "A2AAgent", props))
	}

	// Coverage manifest: preserve every requested target's outcome so a
	// downstream reader can tell "no agents found" (StatusComplete, empty)
	// apart from "we failed to reach the agents" (StatusFailed/Partial).
	// Previously a failed fetch was only logged and silently dropped, which
	// made an all-failed scan indistinguishable from a clean empty one.
	targetOutcomes := make([]ingest.TargetOutcome, 0, len(results))
	statuses := make([]ingest.CollectionStatus, 0, len(results))
	for _, r := range results {
		outcome := ingest.TargetOutcome{Target: r.url, Status: ingest.StatusComplete}
		if r.err != nil {
			outcome.Status = ingest.StatusFailed
			outcome.Error = r.err.Error()
		}
		targetOutcomes = append(targetOutcomes, outcome)
		statuses = append(statuses, outcome.Status)
	}
	data.Meta.Coverage = &ingest.CollectionCoverage{
		Status:                ingest.RollupStatus(statuses...),
		ConstituentCollectors: []string{c.Name()},
		Targets:               targetOutcomes,
		Rules:                 engine.Manifest(),
	}

	return data, nil
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

	agentProps := map[string]any{
		"name":                          card.Name,
		"description":                   card.Description,
		"url":                           card.URL,
		"provider":                      card.Provider,
		"version":                       card.Version,
		"protocol_versions":             card.ProtocolVersions,
		"capabilities":                  card.Capabilities,
		"auth_method":                   card.AuthMethod,
		"is_signed":                     card.IsSigned,
		"signature_valid":               card.SignatureValid,
		"signature_verification_status": card.SignatureStatus,
		"is_https":                      card.IsHTTPS,
		"card_hash":                     card.CardHash,
		"auth_posture":                  AuthPostureScore(card.SecuritySchemes),
		// Canonical, evidence-derived auth scheme (shared vocabulary). The
		// numeric auth_posture above is a heuristic ranking, NOT an assessed
		// assurance level — auth_assurance_state records that OIDC/OAuth here
		// were observed as declared schemes only, not independently verified.
		"auth_scheme":          string(CanonicalAuthScheme(card.SecuritySchemes)),
		"auth_scheme_source":   "agent_card_security_schemes",
		"auth_assurance_state": string(common.AssessmentNotAssessed),
	}

	schemesData := make([]map[string]string, len(card.SecuritySchemes))
	for i, s := range card.SecuritySchemes {
		schemesData[i] = map[string]string{"name": s.Name, "type": s.Type}
	}
	agentProps["security_schemes"] = schemesData

	nodes = append(nodes, common.NewNode(agentID, []string{"A2AAgent"}, agentProps))

	for _, skill := range card.Skills {
		skillID := ingest.ComputeNodeID("A2ASkill", agentID, skill.ID)
		skillProps := map[string]any{
			"id":                     skill.ID,
			"name":                   skill.Name,
			"description":            skill.Description,
			"input_modes":            skill.InputModes,
			"output_modes":           skill.OutputModes,
			"description_hash":       skill.DescriptionHash,
			"has_injection_patterns": skill.HasInjection,
		}
		nodes = append(nodes, common.NewNode(skillID, []string{"A2ASkill"}, skillProps))

		edgeProps := common.NewEdgeProps(scanID, 1.0, 0.1)
		edges = append(edges, common.NewEdge(agentID, skillID, "ADVERTISES_SKILL", "A2AAgent", "A2ASkill", edgeProps))
	}

	hostInfo := common.ClassifyHost(card.URL)
	hostname := hostInfo.Hostname
	if hostname == "" {
		hostname = hostInfo.IP
	}
	if hostname != "" {
		hostID := common.HostNodeID(hostname)
		nodes = append(nodes, common.NewNode(hostID, []string{"Host"}, common.HostNodeProps(hostInfo)))

		edgeProps := common.NewEdgeProps(scanID, 1.0, 0.0)
		edges = append(edges, common.NewEdge(agentID, hostID, "RUNS_ON", "A2AAgent", "Host", edgeProps))
	}

	if card.AuthMethod != "none" {
		identityID := ingest.ComputeNodeID("Identity", agentID, card.AuthMethod)
		identityProps := map[string]any{
			"type":      card.AuthMethod,
			"is_static": card.AuthMethod == "apiKey",
		}
		nodes = append(nodes, common.NewNode(identityID, []string{"Identity"}, identityProps))

		edgeProps := common.NewEdgeProps(scanID, 1.0, 0.0)
		edges = append(edges, common.NewEdge(agentID, identityID, "AUTHENTICATES_WITH", "A2AAgent", "Identity", edgeProps))
	}

	return nodes, edges
}

func agentNodeID(card *AgentCardData) string {
	return ingest.ComputeNodeID("A2AAgent", normalizeBaseURL(card.URL))
}

func hasAuth(cards []*AgentCardData, agentID string) bool {
	for _, c := range cards {
		if agentNodeID(c) == agentID && c.AuthMethod != "none" {
			return true
		}
	}
	return false
}
