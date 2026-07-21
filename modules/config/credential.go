package config

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type CredentialInfo struct {
	Type       string // "envVar", "hardcoded", "vaultRef", "inputPrompt"
	Name       string
	Location   string // "env", "header", or a stable argv position
	AuthMethod common.AuthMethod
	Value      string // SHA-256 hash by default, actual value only if includeValues=true
	ValueHash  string // SHA-256 hash of the original raw value, ALWAYS populated.
	// ValueHash is the cross-collector merge primitive. Even
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

	for _, name := range sortedMapKeys(env) {
		value := env[name]
		if strings.TrimSpace(value) == "" || !isCredentialName(name, engine) {
			continue
		}
		creds = append(creds, classifyAndBuild(name, value, source, "env", includeValues, engine))
	}

	for _, name := range sortedMapKeys(headers) {
		value := headers[name]
		if strings.TrimSpace(value) == "" || !isCredentialName(name, engine) {
			continue
		}
		creds = append(creds, classifyAndBuild(name, value, source, "header", includeValues, engine))
	}

	return creds
}

// ExtractServerCredentials covers every configuration surface that can carry
// authentication material. Raw argv stays in memory; only classified
// Credential evidence (hashes unless explicitly opted in) may enter an ingest
// artifact.
func ExtractServerCredentials(
	server ServerDef,
	includeValues bool,
	engine *rules.Engine,
) []CredentialInfo {
	creds := ExtractCredentials(
		server.Env,
		server.Headers,
		server.Name,
		includeValues,
		engine,
	)
	creds = append(creds, extractArgumentCredentials(
		server.Args,
		server.Name,
		includeValues,
		engine,
	)...)
	if server.Transport == "http" {
		creds = append(creds, extractURLCredentials(
			server.URL,
			server.Name,
			"url",
			includeValues,
			engine,
		)...)
	}
	sort.Slice(creds, func(i, j int) bool {
		if creds[i].Source != creds[j].Source {
			return creds[i].Source < creds[j].Source
		}
		if creds[i].Location != creds[j].Location {
			return creds[i].Location < creds[j].Location
		}
		if creds[i].Name != creds[j].Name {
			return creds[i].Name < creds[j].Name
		}
		return creds[i].ValueHash < creds[j].ValueHash
	})
	return creds
}

func extractURLCredentials(
	rawURL string,
	source string,
	locationPrefix string,
	includeValues bool,
	engine *rules.Engine,
) []CredentialInfo {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return nil
	}
	var credentials []CredentialInfo
	appendCredential := func(name, value, location string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		credentials = append(credentials, classifyAndBuild(
			normalizeArgumentCredentialName(name),
			value,
			source,
			location,
			includeValues,
			engine,
		))
	}
	if parsed.User != nil {
		if password, present := parsed.User.Password(); present && strings.TrimSpace(password) != "" {
			appendCredential("URL_PASSWORD", password, locationPrefix+":userinfo")
		} else if username := parsed.User.Username(); strings.TrimSpace(username) != "" {
			appendCredential("URL_USERINFO", username, locationPrefix+":userinfo")
		}
	}
	query := parsed.Query()
	for _, name := range sortedMapKeys(query) {
		normalized := normalizeArgumentCredentialName(name)
		if !isCredentialName(normalized, engine) {
			continue
		}
		for valueIndex, value := range query[name] {
			appendCredential(
				normalized,
				value,
				fmt.Sprintf("%s:query:%d", locationPrefix, valueIndex),
			)
		}
	}
	if fragment := parsed.Fragment; common.IsLikelySecret(fragment) {
		appendCredential("URL_FRAGMENT", fragment, locationPrefix+":fragment")
	}
	return credentials
}

func extractArgumentCredentials(
	args []string,
	source string,
	includeValues bool,
	engine *rules.Engine,
) []CredentialInfo {
	var creds []CredentialInfo
	seen := make(map[string]bool)
	appendCredential := func(name, value, location string) {
		name = normalizeArgumentCredentialName(name)
		if name == "" || strings.TrimSpace(value) == "" {
			return
		}
		credential := classifyAndBuild(name, value, source, location, includeValues, engine)
		key := credential.Name + "\x00" + credential.Location + "\x00" + credential.ValueHash
		if seen[key] {
			return
		}
		seen[key] = true
		creds = append(creds, credential)
	}

	consumedAsFlagValue := make(map[int]bool)
	for index, argument := range args {
		name, value, hasValue := strings.Cut(argument, "=")
		normalizedName := normalizeArgumentCredentialName(name)
		if hasValue && isCredentialName(normalizedName, engine) {
			appendCredential(normalizedName, value, argumentLocation(index))
			consumedAsFlagValue[index] = true
			continue
		}
		if !hasValue && strings.HasPrefix(strings.TrimSpace(argument), "-") &&
			isCredentialName(normalizedName, engine) && index+1 < len(args) {
			appendCredential(normalizedName, args[index+1], argumentLocation(index+1))
			consumedAsFlagValue[index+1] = true
		}
	}

	for index, argument := range args {
		parsed, err := url.Parse(argument)
		if err == nil && parsed.Scheme != "" {
			if parsed.User != nil {
				if password, present := parsed.User.Password(); present && strings.TrimSpace(password) != "" {
					appendCredential("URL_PASSWORD", password, argumentLocation(index)+":userinfo")
				} else if username := parsed.User.Username(); strings.TrimSpace(username) != "" {
					appendCredential("URL_USERINFO", username, argumentLocation(index)+":userinfo")
				}
			}
			query := parsed.Query()
			for _, name := range sortedMapKeys(query) {
				if !isCredentialName(normalizeArgumentCredentialName(name), engine) {
					continue
				}
				for valueIndex, value := range query[name] {
					appendCredential(name, value, fmt.Sprintf("%s:query:%d", argumentLocation(index), valueIndex))
				}
			}
		}
		if !consumedAsFlagValue[index] && common.IsLikelySecret(argument) {
			appendCredential(
				fmt.Sprintf("ARGV_%d", index),
				argument,
				argumentLocation(index),
			)
		}
	}
	return creds
}

func argumentLocation(index int) string {
	return fmt.Sprintf("arg:%d", index)
}

func normalizeArgumentCredentialName(name string) string {
	name = strings.TrimLeft(strings.TrimSpace(name), "-")
	if name == "" {
		return ""
	}
	var normalized strings.Builder
	for _, char := range name {
		switch {
		case char >= 'a' && char <= 'z':
			normalized.WriteRune(char - ('a' - 'A'))
		case char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
			normalized.WriteRune(char)
		default:
			normalized.WriteByte('_')
		}
	}
	return strings.Trim(normalized.String(), "_")
}

func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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
	if strings.Contains(location, "userinfo") {
		return common.AuthBasic
	}
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
