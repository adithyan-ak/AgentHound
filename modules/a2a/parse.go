package a2a

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type AgentCardData struct {
	Name                 string
	Description          string
	URL                  string
	Provider             string
	Version              string
	SchemaVersion        string
	PresentFields        []string
	ProtocolVersions     []string
	Interfaces           []AgentInterfaceData
	Capabilities         []string
	SecuritySchemes      []SecurityScheme
	SecurityRequirements []SecurityRequirement
	AuthMethod           string
	Skills               []SkillData
	Conformant           bool
	ConformanceErrors    []string
	DescriptionValid     bool
	PreferredURLValid    bool
	SecurityValid        bool
	IsSigned             bool
	SignatureStatus      string
	SignatureKeySource   string
	SignatureKeyTrust    string
	IsHTTPS              bool
	CardHash             string
}

type SkillData struct {
	ID                   string
	Name                 string
	Description          string
	InputModes           []string
	OutputModes          []string
	SecurityRequirements []SecurityRequirement
	DescriptionHash      string
	HasInjection         bool
	Conformant           bool
	ConformanceErrors    []string
}

type SecurityScheme struct {
	Name       string
	Type       string
	Scheme     string
	Conformant bool
}

// SecurityRequirement preserves the wire-level OR-of-AND model. The outer
// slice on AgentCardData is OR; Schemes within one requirement are AND.
type SecurityRequirement struct {
	Schemes    []SecurityRequirementScheme
	Conformant bool
}

type SecurityRequirementScheme struct {
	Name   string
	Scopes []string
}

type AgentInterfaceData struct {
	URL             string
	ProtocolBinding string
	ProtocolVersion string
	Tenant          string
	Preferred       bool
	Conformant      bool
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

func detectVersionWithPathHint(raw map[string]any, pathVersion string) string {
	if _, ok := raw["supportedInterfaces"]; ok {
		return "v1.0"
	}
	if _, ok := raw["url"]; ok {
		return "v0.3.0"
	}
	return pathVersion
}

func ParseAgentCard(ctx context.Context, raw *RawCard, engine *rules.Engine, verifyOpts VerifyOptions) (*AgentCardData, error) {
	switch raw.Version {
	case "v1.0":
		card, err := parseV10(raw.Parsed, raw.CardHash, engine)
		if err != nil {
			return nil, err
		}
		card.IsHTTPS = card.PreferredURLValid &&
			strings.HasPrefix(strings.ToLower(card.URL), "https://")
		result := VerifySignaturesCtx(ctx, raw.Parsed, raw.Version, verifyOpts)
		applyRawCardValidation(card, raw, &result)
		applySignatureResult(card, result)
		return card, nil
	default:
		card, err := parseV030(raw.Parsed, raw.CardHash, engine)
		if err != nil {
			return nil, err
		}
		card.IsHTTPS = card.PreferredURLValid &&
			strings.HasPrefix(strings.ToLower(card.URL), "https://")
		result := VerifySignaturesCtx(ctx, raw.Parsed, raw.Version, verifyOpts)
		applyRawCardValidation(card, raw, &result)
		applySignatureResult(card, result)
		return card, nil
	}
}

func applyRawCardValidation(
	card *AgentCardData,
	raw *RawCard,
	signature *SignatureResult,
) {
	if raw.JSONValidationError == "" {
		return
	}
	card.ConformanceErrors = append(
		card.ConformanceErrors,
		"json: "+raw.JSONValidationError,
	)
	sort.Strings(card.ConformanceErrors)
	card.Conformant = false
	if signature.Signed {
		*signature = SignatureResult{
			Signed:    true,
			Status:    SigStatusMalformed,
			KeySource: SigKeySourceNone,
			KeyTrust:  SigKeyTrustUnknown,
		}
	}
}

func applySignatureResult(card *AgentCardData, res SignatureResult) {
	card.IsSigned = res.Signed
	card.SignatureStatus = res.Status
	card.SignatureKeySource = res.KeySource
	card.SignatureKeyTrust = res.KeyTrust
}

func parseV030(raw map[string]any, cardHash string, engine *rules.Engine) (*AgentCardData, error) {
	card := &AgentCardData{
		Name:             getString(raw, "name"),
		Description:      getString(raw, "description"),
		URL:              getString(raw, "url"),
		Version:          getString(raw, "version"),
		SchemaVersion:    "v0.3.0",
		PresentFields:    presentFields(raw),
		CardHash:         cardHash,
		DescriptionValid: isStringField(raw, "description"),
	}

	card.ConformanceErrors = validateV030Card(raw)

	if provider, ok := raw["provider"].(map[string]any); ok {
		card.Provider = getString(provider, "organization")
	}

	switch pv := raw["protocolVersion"].(type) {
	case string:
		card.ProtocolVersions = []string{strings.TrimSpace(pv)}
	case []any:
		for _, v := range pv {
			if s, ok := v.(string); ok {
				card.ProtocolVersions = append(card.ProtocolVersions, strings.TrimSpace(s))
			}
		}
	}
	card.Interfaces = parseV030Interfaces(raw)
	if len(card.Interfaces) > 0 {
		card.PreferredURLValid = card.Interfaces[0].Conformant
	}

	card.Capabilities = parseCapabilities(raw)

	card.SecuritySchemes = parseV030SecuritySchemes(raw)
	card.ConformanceErrors = append(
		card.ConformanceErrors,
		securitySchemeConformanceErrors(card.SecuritySchemes)...,
	)
	var securityErrors []string
	card.SecurityRequirements, card.SecurityValid, securityErrors = parseV030SecurityRequirements(
		raw["security"],
		card.SecuritySchemes,
	)
	card.ConformanceErrors = append(card.ConformanceErrors, securityErrors...)
	card.AuthMethod = DeriveAuthMethod(card.SecuritySchemes, card.SecurityRequirements)

	if skills, ok := raw["skills"].([]any); ok {
		for index, s := range skills {
			sObj, ok := s.(map[string]any)
			if !ok {
				continue
			}
			skill := parseSkill(sObj, engine, "v0.3.0", index, card.SecuritySchemes)
			card.Skills = append(card.Skills, skill)
		}
	}

	sort.Strings(card.ConformanceErrors)
	card.Conformant = len(card.ConformanceErrors) == 0
	return card, nil
}

func parseV10(raw map[string]any, cardHash string, engine *rules.Engine) (*AgentCardData, error) {
	card := &AgentCardData{
		Name:             getString(raw, "name"),
		Description:      getString(raw, "description"),
		Version:          getString(raw, "version"),
		SchemaVersion:    "v1.0.1",
		PresentFields:    presentFields(raw),
		CardHash:         cardHash,
		DescriptionValid: isStringField(raw, "description"),
	}

	card.ConformanceErrors = validateV10Card(raw)

	if provider, ok := raw["provider"].(map[string]any); ok {
		card.Provider = getString(provider, "organization")
	}

	card.Interfaces = parseV10Interfaces(raw)
	seenPV := make(map[string]bool)
	for _, iface := range card.Interfaces {
		if iface.Preferred {
			card.URL = iface.URL
			card.PreferredURLValid = iface.Conformant
		}
		if iface.ProtocolVersion != "" && !seenPV[iface.ProtocolVersion] {
			seenPV[iface.ProtocolVersion] = true
			card.ProtocolVersions = append(card.ProtocolVersions, iface.ProtocolVersion)
		}
	}

	card.Capabilities = parseCapabilities(raw)

	card.SecuritySchemes = parseV10SecuritySchemes(raw)
	card.ConformanceErrors = append(
		card.ConformanceErrors,
		securitySchemeConformanceErrors(card.SecuritySchemes)...,
	)
	var securityErrors []string
	card.SecurityRequirements, card.SecurityValid, securityErrors = parseV10SecurityRequirements(
		raw["securityRequirements"],
		card.SecuritySchemes,
	)
	card.ConformanceErrors = append(card.ConformanceErrors, securityErrors...)
	card.AuthMethod = DeriveAuthMethod(card.SecuritySchemes, card.SecurityRequirements)

	if skills, ok := raw["skills"].([]any); ok {
		for index, s := range skills {
			sObj, ok := s.(map[string]any)
			if !ok {
				continue
			}
			skill := parseSkill(sObj, engine, "v1.0.1", index, card.SecuritySchemes)
			card.Skills = append(card.Skills, skill)
		}
	}

	sort.Strings(card.ConformanceErrors)
	card.Conformant = len(card.ConformanceErrors) == 0
	return card, nil
}

func parseV030Interfaces(raw map[string]any) []AgentInterfaceData {
	protocolVersion := getString(raw, "protocolVersion")
	preferred := AgentInterfaceData{
		URL:             getString(raw, "url"),
		ProtocolBinding: getString(raw, "preferredTransport"),
		ProtocolVersion: protocolVersion,
		Preferred:       true,
	}
	if preferred.ProtocolBinding == "" {
		preferred.ProtocolBinding = "JSONRPC"
	}
	preferred.Conformant = validInterfaceURL(preferred.URL) &&
		preferred.ProtocolBinding != "" &&
		preferred.ProtocolVersion != ""
	interfaces := []AgentInterfaceData{preferred}

	additional, ok := raw["additionalInterfaces"].([]any)
	if !ok {
		return interfaces
	}
	for _, value := range additional {
		object, ok := value.(map[string]any)
		if !ok {
			interfaces = append(interfaces, AgentInterfaceData{
				ProtocolVersion: protocolVersion,
			})
			continue
		}
		iface := AgentInterfaceData{
			URL:             getString(object, "url"),
			ProtocolBinding: getString(object, "transport"),
			ProtocolVersion: protocolVersion,
		}
		iface.Conformant = validInterfaceURL(iface.URL) &&
			iface.ProtocolBinding != "" &&
			iface.ProtocolVersion != ""
		interfaces = append(interfaces, iface)
	}
	return interfaces
}

func parseV10Interfaces(raw map[string]any) []AgentInterfaceData {
	values, ok := raw["supportedInterfaces"].([]any)
	if !ok {
		return nil
	}
	interfaces := make([]AgentInterfaceData, 0, len(values))
	for index, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			interfaces = append(interfaces, AgentInterfaceData{
				Preferred: index == 0,
			})
			continue
		}
		iface := AgentInterfaceData{
			URL:             getString(object, "url"),
			ProtocolBinding: getString(object, "protocolBinding"),
			ProtocolVersion: getString(object, "protocolVersion"),
			Tenant:          getString(object, "tenant"),
			Preferred:       index == 0,
		}
		iface.Conformant = validInterfaceURL(iface.URL) &&
			iface.ProtocolBinding != "" &&
			iface.ProtocolVersion != ""
		interfaces = append(interfaces, iface)
	}
	return interfaces
}

func parseCapabilities(raw map[string]any) []string {
	capabilities, ok := raw["capabilities"].(map[string]any)
	if !ok {
		return nil
	}
	var result []string
	for key, value := range capabilities {
		if enabled, ok := value.(bool); ok && enabled {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}

func presentFields(raw map[string]any) []string {
	fields := make([]string, 0, len(raw))
	for field := range raw {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

// parseSkill parses an A2A AgentSkill while retaining its independent
// conformance state. Invalid skill observations are kept, but graph
// construction does not emit functional ADVERTISES_SKILL edges for them.
func parseSkill(
	s map[string]any,
	engine *rules.Engine,
	schemaVersion string,
	index int,
	schemes []SecurityScheme,
) SkillData {
	id := getString(s, "id")
	name := getString(s, "name")
	desc := getString(s, "description")

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

	skill := SkillData{
		ID:              id,
		Name:            name,
		Description:     desc,
		InputModes:      inputModes,
		OutputModes:     outputModes,
		DescriptionHash: descHash,
		HasInjection:    hasInj,
	}
	path := "skills[" + strconv.Itoa(index) + "]"
	skill.ConformanceErrors = validateSkill(s, path)
	if schemaVersion == "v1.0.1" {
		var securityErrors []string
		skill.SecurityRequirements, _, securityErrors = parseV10SecurityRequirements(
			s["securityRequirements"],
			schemes,
		)
		skill.ConformanceErrors = append(
			skill.ConformanceErrors,
			prefixConformanceErrors(path+".", securityErrors)...,
		)
	} else {
		var securityErrors []string
		skill.SecurityRequirements, _, securityErrors = parseV030SecurityRequirements(
			s["security"],
			schemes,
		)
		skill.ConformanceErrors = append(
			skill.ConformanceErrors,
			prefixConformanceErrors(path+".", securityErrors)...,
		)
	}
	sort.Strings(skill.ConformanceErrors)
	skill.Conformant = len(skill.ConformanceErrors) == 0
	return skill
}

func prefixConformanceErrors(prefix string, errors []string) []string {
	result := make([]string, len(errors))
	for index, value := range errors {
		result[index] = prefix + value
	}
	return result
}

func getString(m map[string]any, key string) string {
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
