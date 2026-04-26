package mcp

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type ToolSignals struct {
	DescriptionHash    string
	CapabilitySurface  []string
	HasInjection       bool
	HasCrossReferences bool
	Annotations        map[string]any
}

type ResourceSignals struct {
	URIScheme   string
	Sensitivity string
}

func computeToolSignals(tool *mcpsdk.Tool, allToolNames map[string]bool, engine *rules.Engine) ToolSignals {
	schemaMap := inputSchemaAsMap(tool.InputSchema)

	sig := ToolSignals{
		DescriptionHash: common.DescriptionHash(tool.Name, tool.Description, schemaMap),
	}

	combined := tool.Name + " " + tool.Description
	if schemaMap != nil {
		if props, ok := schemaMap["properties"].(map[string]any); ok {
			for key := range props {
				combined += " " + key
			}
		}
	}
	fields := map[string]string{
		"tool.description": tool.Description,
		"tool.name":        tool.Name,
		"tool.combined":    combined,
	}
	matches := engine.EvaluateAll("mcp", fields)

	capSet := make(map[string]bool)
	for _, m := range matches {
		switch m.Emit.FindingType {
		case "has_injection_patterns":
			sig.HasInjection = true
		case "capability_classification":
			if v, ok := m.Emit.PropertyValue.(string); ok {
				capSet[v] = true
			}
		}
	}
	for cap := range capSet {
		sig.CapabilitySurface = append(sig.CapabilitySurface, cap)
	}
	sort.Strings(sig.CapabilitySurface)

	if tool.Description != "" {
		descLower := strings.ToLower(tool.Description)
		for name := range allToolNames {
			if name != tool.Name && strings.Contains(descLower, strings.ToLower(name)) {
				sig.HasCrossReferences = true
				break
			}
		}
	}

	sig.Annotations = flattenAnnotations(tool.Annotations)

	return sig
}

func flattenAnnotations(ann *mcpsdk.ToolAnnotations) map[string]any {
	if ann == nil {
		return nil
	}
	m := make(map[string]any)
	m["read_only_hint"] = ann.ReadOnlyHint
	m["idempotent_hint"] = ann.IdempotentHint
	if ann.DestructiveHint != nil {
		m["destructive_hint"] = *ann.DestructiveHint
	}
	if ann.OpenWorldHint != nil {
		m["open_world_hint"] = *ann.OpenWorldHint
	}
	if ann.Title != "" {
		m["title"] = ann.Title
	}
	return m
}

func computeResourceSignals(uri string, engine *rules.Engine) ResourceSignals {
	var sig ResourceSignals

	fields := map[string]string{"resource.uri": uri}
	matches := engine.EvaluateAll("mcp", fields)

	bestSeverity := ""
	severityRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

	for _, m := range matches {
		if !strings.Contains(m.Emit.FindingType, "sensitivity") {
			continue
		}
		sev := ""
		if v, ok := m.Emit.PropertyValue.(string); ok {
			sev = v
		}
		if bestSeverity == "" {
			bestSeverity = sev
		} else if rank, ok := severityRank[sev]; ok {
			if bestRank, ok2 := severityRank[bestSeverity]; ok2 && rank < bestRank {
				bestSeverity = sev
			}
		}
	}
	if bestSeverity == "" {
		bestSeverity = "low"
	}
	sig.Sensitivity = bestSeverity

	if u, err := url.Parse(uri); err == nil && u.Scheme != "" {
		sig.URIScheme = u.Scheme
	}

	return sig
}

func inputSchemaAsMap(schema any) map[string]any {
	if schema == nil {
		return nil
	}

	if m, ok := schema.(map[string]any); ok {
		return m
	}

	if s, ok := schema.(string); ok {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err == nil {
			return m
		}
	}

	data, err := json.Marshal(schema)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}
