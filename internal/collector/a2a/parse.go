package a2a

import (
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/internal/collector/common"
	"github.com/adithyan-ak/agenthound/internal/rules"
)

type AgentCardData struct {
	Name             string
	Description      string
	URL              string
	Provider         string
	Version          string
	ProtocolVersions []string
	Capabilities     []string
	SecuritySchemes  []SecurityScheme
	AuthMethod       string
	Skills           []SkillData
	IsSigned         bool
	SignatureValid   bool
	IsHTTPS          bool
	CardHash         string
}

type SkillData struct {
	ID              string
	Name            string
	Description     string
	InputModes      []string
	OutputModes     []string
	DescriptionHash string
	HasInjection    bool
}

type SecurityScheme struct {
	Name string
	Type string
}

func DetectVersion(raw map[string]any) string {
	if _, ok := raw["supportedInterfaces"]; ok {
		return "v1.0"
	}
	if _, ok := raw["url"]; ok {
		return "v0.3.0"
	}
	return "v0.3.0"
}

func ParseAgentCard(raw *RawCard, engine *rules.Engine) (*AgentCardData, error) {
	switch raw.Version {
	case "v1.0":
		card, err := parseV10(raw.Parsed, raw.CardHash, engine)
		if err != nil {
			return nil, err
		}
		card.IsHTTPS = strings.HasPrefix(raw.URL, "https://")
		signed, valid := VerifySignatures(raw.Body, raw.Parsed)
		card.IsSigned = signed
		card.SignatureValid = valid
		return card, nil
	default:
		card, err := parseV030(raw.Parsed, raw.CardHash, engine)
		if err != nil {
			return nil, err
		}
		card.IsHTTPS = strings.HasPrefix(raw.URL, "https://")
		signed, valid := VerifySignatures(raw.Body, raw.Parsed)
		card.IsSigned = signed
		card.SignatureValid = valid
		return card, nil
	}
}

func parseV030(raw map[string]any, cardHash string, engine *rules.Engine) (*AgentCardData, error) {
	card := &AgentCardData{
		Name:        getString030(raw, "name"),
		Description: getString030(raw, "description"),
		URL:         getString030(raw, "url"),
		Version:     getString030(raw, "version"),
		CardHash:    cardHash,
	}

	if card.Name == "" {
		return nil, fmt.Errorf("v0.3.0 agent card missing required field: name")
	}

	if provider, ok := raw["provider"].(map[string]any); ok {
		card.Provider = getString030(provider, "organization")
	}

	switch pv := raw["protocolVersion"].(type) {
	case string:
		card.ProtocolVersions = []string{pv}
	case []any:
		for _, v := range pv {
			if s, ok := v.(string); ok {
				card.ProtocolVersions = append(card.ProtocolVersions, s)
			}
		}
	}

	if caps, ok := raw["capabilities"].(map[string]any); ok {
		for key, val := range caps {
			if b, ok := val.(bool); ok && b {
				card.Capabilities = append(card.Capabilities, key)
			}
		}
	}

	card.SecuritySchemes = parseSecuritySchemes(raw)
	card.AuthMethod = DeriveAuthMethod(card.SecuritySchemes, getSecurityRefs(raw))

	if skills, ok := raw["skills"].([]any); ok {
		for _, s := range skills {
			sObj, ok := s.(map[string]any)
			if !ok {
				continue
			}
			skill := parseSkillV030(sObj, engine)
			card.Skills = append(card.Skills, skill)
		}
	}

	return card, nil
}

func parseV10(raw map[string]any, cardHash string, engine *rules.Engine) (*AgentCardData, error) {
	card := &AgentCardData{
		Name:        getString030(raw, "name"),
		Description: getString030(raw, "description"),
		CardHash:    cardHash,
	}

	if card.Name == "" {
		return nil, fmt.Errorf("v1.0 agent card missing required field: name")
	}

	if provider, ok := raw["provider"].(map[string]any); ok {
		card.Provider = getString030(provider, "organization")
	}

	if ifaces, ok := raw["supportedInterfaces"].([]any); ok {
		for _, iface := range ifaces {
			ifObj, ok := iface.(map[string]any)
			if !ok {
				continue
			}
			ifType := getString030(ifObj, "type")
			if strings.EqualFold(ifType, "A2A") {
				if u := getString030(ifObj, "url"); u != "" {
					card.URL = u
				}
				if pv := getString030(ifObj, "protocolVersion"); pv != "" {
					card.ProtocolVersions = append(card.ProtocolVersions, pv)
				}
			}
		}
	}

	if caps, ok := raw["capabilities"].(map[string]any); ok {
		for key, val := range caps {
			if b, ok := val.(bool); ok && b {
				card.Capabilities = append(card.Capabilities, key)
			}
		}
	}

	card.SecuritySchemes = parseSecuritySchemes(raw)
	card.AuthMethod = DeriveAuthMethod(card.SecuritySchemes, getSecurityRefs(raw))

	if skills, ok := raw["skills"].([]any); ok {
		for _, s := range skills {
			sObj, ok := s.(map[string]any)
			if !ok {
				continue
			}
			skill := parseSkillV10(sObj, engine)
			card.Skills = append(card.Skills, skill)
		}
	}

	return card, nil
}

func parseSecuritySchemes(raw map[string]any) []SecurityScheme {
	schemes, ok := raw["securitySchemes"].(map[string]any)
	if !ok {
		return nil
	}
	var result []SecurityScheme
	for name, v := range schemes {
		obj, ok := v.(map[string]any)
		if !ok {
			continue
		}
		t := getString030(obj, "type")
		if t == "" {
			continue
		}
		result = append(result, SecurityScheme{Name: name, Type: t})
	}
	return result
}

func getSecurityRefs(raw map[string]any) []any {
	sec, ok := raw["security"].([]any)
	if !ok {
		return nil
	}
	return sec
}

func parseSkillV030(s map[string]any, engine *rules.Engine) SkillData {
	id := getString030(s, "id")
	name := getString030(s, "name")
	desc := getString030(s, "description")

	var inputModes, outputModes []string
	if is, ok := s["inputSchema"].(map[string]any); ok {
		if t := getString030(is, "type"); t != "" {
			inputModes = append(inputModes, "application/json")
		}
	}
	if _, ok := s["outputSchema"].(map[string]any); ok {
		outputModes = append(outputModes, "application/json")
	}

	descHash := common.DescriptionHash(name, desc, nil)

	hasInj := false
	matches := engine.EvaluateAll("a2a", map[string]string{
		"skill.description": desc,
	})
	for _, m := range matches {
		if m.Emit.FindingType == "has_injection_patterns" {
			hasInj = true
			break
		}
	}

	return SkillData{
		ID:              id,
		Name:            name,
		Description:     desc,
		InputModes:      inputModes,
		OutputModes:     outputModes,
		DescriptionHash: descHash,
		HasInjection:    hasInj,
	}
}

func parseSkillV10(s map[string]any, engine *rules.Engine) SkillData {
	id := getString030(s, "id")
	name := getString030(s, "name")
	desc := getString030(s, "description")

	inputModes := toStrSlice(s["inputModes"])
	outputModes := toStrSlice(s["outputModes"])

	descHash := common.DescriptionHash(name, desc, nil)

	hasInj := false
	matches := engine.EvaluateAll("a2a", map[string]string{
		"skill.description": desc,
	})
	for _, m := range matches {
		if m.Emit.FindingType == "has_injection_patterns" {
			hasInj = true
			break
		}
	}

	return SkillData{
		ID:              id,
		Name:            name,
		Description:     desc,
		InputModes:      inputModes,
		OutputModes:     outputModes,
		DescriptionHash: descHash,
		HasInjection:    hasInj,
	}
}

func getString030(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func toStrSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
