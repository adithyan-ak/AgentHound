package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	pathpkg "path"
	"sort"
	"strings"
)

// CanonicalCoverageKey builds an opaque, stable ownership key from a
// collector, scope kind, and caller-canonicalized scope identity. Hashing keeps
// target URLs, command lines, and local config paths out of Neo4j ownership
// tokens and exported coverage metadata.
func CanonicalCoverageKey(collector, scopeKind, canonicalScope string) string {
	collector = strings.ToLower(strings.TrimSpace(collector))
	scopeKind = strings.ToLower(strings.TrimSpace(scopeKind))
	canonicalScope = strings.TrimSpace(canonicalScope)
	if collector == "" {
		return ""
	}
	if scopeKind == "" || canonicalScope == "" {
		return collector
	}
	sum := sha256.Sum256([]byte(
		collector + "\x00" + scopeKind + "\x00" + canonicalScope,
	))
	return collector + ":" + scopeKind + ":sha256:" + hex.EncodeToString(sum[:])
}

// CollectorRootCoverageKey returns the stable root key shared by exhaustive
// and targeted attempts for one collector.
func CollectorRootCoverageKey(collector string) string {
	return CanonicalCoverageKey(collector, "root", "collect")
}

// CanonicalURLScope normalizes URL spelling for coverage identity without
// changing the actual collector target. Credentials and fragments are not part
// of scope identity; query parameters are sorted deterministically.
func CanonicalURLScope(raw string) string {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return raw
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") ||
		(parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	switch {
	case port != "":
		parsed.Host = net.JoinHostPort(hostname, port)
	case strings.Contains(hostname, ":"):
		parsed.Host = "[" + hostname + "]"
	default:
		parsed.Host = hostname
	}
	parsed.User = nil
	parsed.Fragment = ""
	parsed.RawFragment = ""
	parsed.RawQuery = parsed.Query().Encode()
	cleanPath := pathpkg.Clean(parsed.Path)
	if cleanPath == "." || cleanPath == "/" {
		cleanPath = ""
	}
	parsed.Path = cleanPath
	parsed.RawPath = ""
	return parsed.String()
}

// TagObservationDomain marks every fact in a collector result with the
// canonical coverage domain that observed it. Merged artifacts must preserve
// these tags so shared facts can keep multiple active owners.
func TagObservationDomain(graph *GraphData, domain string) {
	domain = strings.TrimSpace(domain)
	if graph == nil || domain == "" {
		return
	}
	for i := range graph.Nodes {
		graph.Nodes[i].ObservationDomains = appendUniqueSorted(
			graph.Nodes[i].ObservationDomains,
			domain,
		)
	}
	for i := range graph.Edges {
		graph.Edges[i].ObservationDomains = appendUniqueSorted(
			graph.Edges[i].ObservationDomains,
			domain,
		)
	}
}

// MergeObservationDomains returns the sorted union of observation ownership
// keys within one contribution. Collector aggregation must keep contributions
// from distinct owner domains separate until the graph writer fingerprints
// each owner independently.
func MergeObservationDomains(groups ...[]string) []string {
	seen := make(map[string]bool)
	var merged []string
	for _, group := range groups {
		for _, value := range group {
			value = strings.TrimSpace(value)
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			merged = append(merged, value)
		}
	}
	sort.Strings(merged)
	return merged
}

func appendUniqueSorted(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	sort.Strings(values)
	return values
}

func outcomeCoverageKey(outcome CollectionOutcome) string {
	return strings.TrimSpace(outcome.CoverageKey)
}

// CoverageStates returns the best supported state for each declared coverage
// key from its explicit scoped outcomes.
func CoverageStates(report *CollectionReport) map[string]OutcomeState {
	states := make(map[string]OutcomeState)
	if report == nil {
		return states
	}

	keys := append([]string(nil), report.CoverageKeys...)
	sort.Strings(keys)
	for _, key := range keys {
		if key == "" {
			continue
		}
		var outcomes []CollectionOutcome
		for _, outcome := range report.Outcomes {
			if outcomeCoverageKey(outcome) == key {
				outcomes = append(outcomes, outcome)
			}
		}
		if len(outcomes) > 0 {
			states[key] = AggregateOutcomeState(outcomes)
		} else {
			states[key] = OutcomeUnknown
		}
	}
	return states
}

func CompleteCoverageDomains(report *CollectionReport) []string {
	states := CoverageStates(report)
	domains := make([]string, 0, len(states))
	for domain, state := range states {
		if state == OutcomeComplete {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	return domains
}

// CompleteAuthoritativeRoots returns only exhaustive root declarations whose
// root and complete active child set were all observed successfully.
func CompleteAuthoritativeRoots(report *CollectionReport) []CoverageRoot {
	if report == nil {
		return nil
	}
	states := CoverageStates(report)
	var roots []CoverageRoot
	for _, root := range report.AuthoritativeRoots {
		if states[root.CoverageKey] != OutcomeComplete {
			continue
		}
		children := append([]string(nil), root.ChildCoverageKeys...)
		complete := true
		for _, child := range children {
			if states[child] != OutcomeComplete {
				complete = false
				break
			}
		}
		if !complete {
			continue
		}
		sort.Strings(children)
		roots = append(roots, CoverageRoot{
			CoverageKey:       root.CoverageKey,
			ChildCoverageKeys: children,
		})
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].CoverageKey < roots[j].CoverageKey
	})
	return roots
}

func CollectionCoverageComplete(report *CollectionReport) bool {
	if report == nil || len(report.CoverageKeys) == 0 {
		return false
	}
	keys := make(map[string]bool, len(report.CoverageKeys))
	for _, key := range report.CoverageKeys {
		if key = strings.TrimSpace(key); key != "" {
			keys[key] = true
		}
	}
	if len(keys) == 0 {
		return false
	}
	states := CoverageStates(report)
	if len(states) != len(keys) {
		return false
	}
	for _, state := range states {
		if state != OutcomeComplete {
			return false
		}
	}
	return true
}
