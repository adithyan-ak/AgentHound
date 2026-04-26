package config

import (
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type CredentialInfo struct {
	Type        string // "envVar", "hardcoded", "vaultRef", "inputPrompt"
	Name        string
	Value       string // SHA-256 hash by default, actual value only if includeValues=true
	Source      string
	IsExposed   bool
	HighEntropy bool
	Format      string // "openai", "anthropic", "github", "slack", "aws", "generic"
}

func ExtractCredentials(env map[string]string, headers map[string]string, source string, includeValues bool, engine *rules.Engine) []CredentialInfo {
	var creds []CredentialInfo

	for name, value := range env {
		if !isCredentialName(name, engine) {
			continue
		}
		creds = append(creds, classifyAndBuild(name, value, source, includeValues, engine))
	}

	for name, value := range headers {
		if !isCredentialName(name, engine) {
			continue
		}
		creds = append(creds, classifyAndBuild(name, value, source, includeValues, engine))
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

func classifyAndBuild(name, value, source string, includeValues bool, engine *rules.Engine) CredentialInfo {
	ci := CredentialInfo{
		Name:   name,
		Source: source,
		Format: detectFormat(value, engine),
		Type:   classifyCredentialType(name, value, engine),
	}

	switch ci.Type {
	case "envVar":
		ci.IsExposed = false
	case "vaultRef":
		ci.IsExposed = false
	default:
		ci.IsExposed = true
		ci.HighEntropy = common.IsLikelySecret(value)
	}

	if includeValues {
		ci.Value = value
	} else {
		ci.Value = common.HashSHA256(value)
	}

	return ci
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
