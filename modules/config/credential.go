package config

import (
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type CredentialInfo struct {
	Type       string // "envVar", "hardcoded", "vaultRef", "inputPrompt"
	Name       string
	Location   string // "env" or "header"
	AuthMethod common.AuthMethod
	Value      string // SHA-256 hash by default, actual value only if includeValues=true
	ValueHash  string // SHA-256 hash of the original raw value, ALWAYS populated.
	// ValueHash is the cross-collector merge primitive (v0.2). Even
	// when includeValues=false replaces Value with the same hash, the
	// LiteLLM Looter (which never sees the hashed form) needs an
	// independent always-populated field to set on its Credential
	// emissions so the cross_service_credential_chain post-processor
	// can join Config Collector emissions to Looter emissions on this
	// property. See sdk/common/hasher.go HashCredentialValue.
	Source         string
	IsExposed      bool
	HighEntropy    bool
	Format         string // "openai", "anthropic", "github", "slack", "aws", "generic"
	IdentityBasis  common.CredentialIdentityBasis
	MaterialStatus common.CredentialMaterialStatus
	ExposureStatus common.CredentialExposureStatus
}

func ExtractCredentials(env map[string]string, headers map[string]string, source string, includeValues bool, engine *rules.Engine) []CredentialInfo {
	var creds []CredentialInfo

	for name, value := range env {
		if !isCredentialName(name, engine) {
			continue
		}
		creds = append(creds, classifyAndBuild(name, value, source, "env", includeValues, engine))
	}

	for name, value := range headers {
		if !isCredentialName(name, engine) {
			continue
		}
		creds = append(creds, classifyAndBuild(name, value, source, "header", includeValues, engine))
	}

	return creds
}

func classifyCredentialType(name, value string, engine *rules.Engine) string {
	if isVaultRef(value, engine) {
		return "vaultRef"
	}
	if isEnvRef(value) {
		return "envVar"
	}
	return "hardcoded"
}

func classifyAndBuild(name, value, source, location string, includeValues bool, engine *rules.Engine) CredentialInfo {
	material := credentialMaterial(name, value, location)
	ci := CredentialInfo{
		Name:          name,
		Location:      location,
		AuthMethod:    credentialAuthMethod(name, value, location),
		Source:        source,
		Format:        detectFormat(material, engine),
		Type:          classifyCredentialType(name, material, engine),
		ValueHash:     common.HashCredentialValue(material),
		IdentityBasis: common.CredentialIdentityValueHash,
	}

	switch ci.Type {
	case "envVar":
		ci.IsExposed = false
		ci.MaterialStatus = common.CredentialMaterialUnobserved
		ci.ExposureStatus = common.CredentialExposureNotObserved
	case "vaultRef":
		ci.IsExposed = false
		ci.MaterialStatus = common.CredentialMaterialUnobserved
		ci.ExposureStatus = common.CredentialExposureNotObserved
	default:
		ci.IsExposed = true
		ci.HighEntropy = common.IsLikelySecret(material)
		ci.MaterialStatus = common.CredentialMaterialObserved
		ci.ExposureStatus = common.CredentialExposureExposed
	}

	if includeValues {
		ci.Value = material
	} else {
		ci.Value = ci.ValueHash
	}

	return ci
}

// credentialMaterial removes a recognized HTTP Authorization scheme from the
// credential identity. "Bearer <token>" and "Basic <value>" describe the
// authentication mechanism plus credential material; the scheme is not part
// of the reusable secret and must not poison cross-collector value_hash joins.
// Unknown/custom schemes remain byte-for-byte intact because stripping an
// unrecognized prefix would invent a credential boundary.
func credentialMaterial(name, value, location string) string {
	if location != "header" || !strings.EqualFold(name, "Authorization") {
		return value
	}
	trimmed := strings.TrimSpace(value)
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return value
	}
	method, recognized := common.RecognizeAuthMethod(fields[0])
	if !recognized || method == common.AuthNone || method == common.AuthUnknown {
		return value
	}
	return strings.TrimSpace(trimmed[len(fields[0]):])
}

func credentialAuthMethod(name, value, location string) common.AuthMethod {
	upperName := strings.ToUpper(name)
	if strings.Contains(upperName, "OAUTH") || strings.Contains(upperName, "CLIENT_ID") {
		return common.AuthOAuth
	}
	if location == "header" && strings.EqualFold(name, "Authorization") {
		fields := strings.Fields(value)
		if len(fields) > 0 {
			if method, ok := common.RecognizeAuthMethod(fields[0]); ok &&
				method != common.AuthNone && method != common.AuthUnknown {
				return method
			}
		}
		return common.AuthCustom
	}
	if strings.Contains(upperName, "KEY") || strings.Contains(upperName, "TOKEN") ||
		strings.Contains(upperName, "SECRET") || strings.Contains(upperName, "AUTH") {
		return common.AuthAPIKey
	}
	return common.AuthCustom
}

func isCredentialName(name string, engine *rules.Engine) bool {
	matches := engine.EvaluateAll("config", map[string]string{
		"credential.name": name,
	})
	for _, m := range matches {
		if m.Emit.FindingType == "credential_detected" {
			return true
		}
	}
	return false
}

func isVaultRef(value string, engine *rules.Engine) bool {
	matches := engine.EvaluateAll("config", map[string]string{
		"credential.value": value,
	})
	for _, m := range matches {
		if m.Emit.FindingType == "credential_type" {
			if v, ok := m.Emit.PropertyValue.(string); ok && v == "vaultRef" {
				return true
			}
		}
	}
	return false
}

func isEnvRef(value string) bool {
	return strings.HasPrefix(value, "$") || strings.HasPrefix(value, "${")
}

func detectFormat(value string, engine *rules.Engine) string {
	matches := engine.EvaluateAll("config", map[string]string{
		"credential.value": value,
	})
	for _, m := range matches {
		if m.Emit.FindingType == "credential_format" {
			return formatFromMatchedText(m.Text)
		}
	}
	return "generic"
}

func formatFromMatchedText(text string) string {
	if strings.HasPrefix(text, "sk-ant-") {
		return "anthropic"
	}
	if strings.HasPrefix(text, "sk-") {
		return "openai"
	}
	if strings.HasPrefix(text, "xoxb-") || strings.HasPrefix(text, "xoxp-") || strings.HasPrefix(text, "xoxs-") {
		return "slack"
	}
	if strings.HasPrefix(text, "ghp_") || strings.HasPrefix(text, "gho_") || strings.HasPrefix(text, "ghs_") {
		return "github"
	}
	if strings.HasPrefix(text, "AKIA") {
		return "aws"
	}
	return "generic"
}
