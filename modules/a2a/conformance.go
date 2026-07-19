package a2a

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func validateV030Card(raw map[string]any) []string {
	var errors []string
	for _, field := range []string{
		"name",
		"description",
		"url",
		"version",
		"protocolVersion",
	} {
		errors = append(errors, validateRequiredString(raw, field)...)
	}
	for _, field := range []string{"name", "url", "version", "protocolVersion"} {
		errors = append(errors, validateNonEmptyString(raw, field)...)
	}
	if value, ok := raw["url"].(string); ok && !validHTTPURL(value) {
		errors = append(errors, "url: must be an absolute HTTP(S) URL")
	}
	errors = append(errors, validateRequiredObject(raw, "capabilities")...)
	for _, field := range []string{"defaultInputModes", "defaultOutputModes", "skills"} {
		errors = append(errors, validateRequiredArray(raw, field)...)
	}
	for _, field := range []string{"defaultInputModes", "defaultOutputModes"} {
		errors = append(errors, validateStringArray(raw, field)...)
	}

	if provider, exists := raw["provider"]; exists {
		object, ok := provider.(map[string]any)
		if !ok {
			errors = append(errors, "provider: must be an object")
		} else {
			errors = append(errors, validateRequiredString(object, "provider.url")...)
			errors = append(errors, validateRequiredString(object, "provider.organization")...)
			errors = append(errors, validateNonEmptyString(object, "provider.organization")...)
			if value, ok := object["url"].(string); ok && !validHTTPURL(value) {
				errors = append(errors, "provider.url: must be an absolute HTTP(S) URL")
			}
		}
	}
	errors = append(errors, validateSecuritySchemesContainer(raw)...)
	if interfaces, ok := raw["additionalInterfaces"].([]any); ok {
		for index, value := range interfaces {
			path := fmt.Sprintf("additionalInterfaces[%d]", index)
			object, ok := value.(map[string]any)
			if !ok {
				errors = append(errors, path+": must be an object")
				continue
			}
			errors = append(errors, validateRequiredString(object, path+".url")...)
			errors = append(errors, validateRequiredString(object, path+".transport")...)
			errors = append(errors, validateNonEmptyStringAtPath(object, "transport", path+".transport")...)
			if value, ok := object["url"].(string); ok && !validInterfaceURL(value) {
				errors = append(errors, path+".url: must be an absolute HTTP(S) or WS(S) URL")
			}
		}
	}
	errors = append(errors, validateSkills(raw)...)
	errors = append(errors, validateSignatureObjects(raw)...)
	sort.Strings(errors)
	return errors
}

func validateV10Card(raw map[string]any) []string {
	var errors []string
	for _, field := range []string{"name", "description", "version"} {
		errors = append(errors, validateRequiredString(raw, field)...)
	}
	for _, field := range []string{"name", "version"} {
		errors = append(errors, validateNonEmptyString(raw, field)...)
	}
	errors = append(errors, validateRequiredObject(raw, "capabilities")...)
	for _, field := range []string{
		"supportedInterfaces",
		"defaultInputModes",
		"defaultOutputModes",
		"skills",
	} {
		errors = append(errors, validateRequiredArray(raw, field)...)
	}
	for _, field := range []string{"defaultInputModes", "defaultOutputModes"} {
		errors = append(errors, validateStringArray(raw, field)...)
	}

	if provider, exists := raw["provider"]; exists {
		object, ok := provider.(map[string]any)
		if !ok {
			errors = append(errors, "provider: must be an object")
		} else {
			errors = append(errors, validateRequiredString(object, "provider.url")...)
			errors = append(errors, validateRequiredString(object, "provider.organization")...)
			errors = append(errors, validateNonEmptyString(object, "provider.organization")...)
			if value, ok := object["url"].(string); ok && !validHTTPURL(value) {
				errors = append(errors, "provider.url: must be an absolute HTTP(S) URL")
			}
		}
	}
	errors = append(errors, validateSecuritySchemesContainer(raw)...)
	if interfaces, ok := raw["supportedInterfaces"].([]any); ok {
		for index, value := range interfaces {
			path := fmt.Sprintf("supportedInterfaces[%d]", index)
			object, ok := value.(map[string]any)
			if !ok {
				errors = append(errors, path+": must be an object")
				continue
			}
			errors = append(errors, validateRequiredString(object, path+".url")...)
			errors = append(errors, validateRequiredString(object, path+".protocolBinding")...)
			errors = append(errors, validateRequiredString(object, path+".protocolVersion")...)
			errors = append(errors, validateNonEmptyStringAtPath(object, "protocolBinding", path+".protocolBinding")...)
			errors = append(errors, validateNonEmptyStringAtPath(object, "protocolVersion", path+".protocolVersion")...)
			if value, ok := object["url"].(string); ok && !validInterfaceURL(value) {
				errors = append(errors, path+".url: must be an absolute HTTP(S) or WS(S) URL")
			}
		}
	}
	errors = append(errors, validateSkills(raw)...)
	errors = append(errors, validateSignatureObjects(raw)...)
	sort.Strings(errors)
	return errors
}

func validateSkills(raw map[string]any) []string {
	values, ok := raw["skills"].([]any)
	if !ok {
		return nil
	}
	var errors []string
	for index, value := range values {
		path := fmt.Sprintf("skills[%d]", index)
		object, ok := value.(map[string]any)
		if !ok {
			errors = append(errors, path+": must be an object")
			continue
		}
		errors = append(errors, validateSkill(object, path)...)
	}
	return errors
}

func validateSkill(raw map[string]any, path string) []string {
	var errors []string
	for _, field := range []string{"id", "name", "description"} {
		errors = append(errors, validateRequiredString(raw, path+"."+field)...)
	}
	for _, field := range []string{"id", "name"} {
		errors = append(errors, validateNonEmptyStringAtPath(raw, field, path+"."+field)...)
	}
	errors = append(errors, validateRequiredArrayAtPath(raw, "tags", path+".tags")...)
	errors = append(errors, validateStringArrayAtPath(raw, "tags", path+".tags")...)
	for _, field := range []string{"examples", "inputModes", "outputModes"} {
		errors = append(
			errors,
			validateOptionalStringArrayAtPath(raw, field, path+"."+field)...,
		)
	}
	return errors
}

func validateOptionalStringArrayAtPath(
	raw map[string]any,
	key string,
	path string,
) []string {
	value, exists := raw[key]
	if !exists || value == nil {
		return nil
	}
	array, ok := value.([]any)
	if !ok {
		return []string{path + ": must be an array"}
	}
	for index, item := range array {
		if _, ok := item.(string); !ok {
			return []string{fmt.Sprintf("%s[%d]: must be a string", path, index)}
		}
	}
	return nil
}

func validateRequiredString(raw map[string]any, path string) []string {
	key := finalPathComponent(path)
	value, exists := raw[key]
	if !exists {
		return []string{path + ": required field is missing"}
	}
	if _, ok := value.(string); !ok {
		return []string{path + ": required field must be a string"}
	}
	return nil
}

func validateRequiredObject(raw map[string]any, path string) []string {
	key := finalPathComponent(path)
	value, exists := raw[key]
	if !exists {
		return []string{path + ": required field is missing"}
	}
	if _, ok := value.(map[string]any); !ok {
		return []string{path + ": required field must be an object"}
	}
	return nil
}

func validateNonEmptyString(raw map[string]any, key string) []string {
	return validateNonEmptyStringAtPath(raw, key, key)
}

func validateNonEmptyStringAtPath(
	raw map[string]any,
	key string,
	path string,
) []string {
	value, exists := raw[key]
	if !exists {
		return nil
	}
	text, ok := value.(string)
	if ok && strings.TrimSpace(text) == "" {
		return []string{path + ": must not be empty"}
	}
	return nil
}

func validateRequiredArray(raw map[string]any, path string) []string {
	return validateRequiredArrayAtPath(raw, finalPathComponent(path), path)
}

func validateRequiredArrayAtPath(raw map[string]any, key, path string) []string {
	value, exists := raw[key]
	if !exists {
		return []string{path + ": required field is missing"}
	}
	array, ok := value.([]any)
	if !ok {
		return []string{path + ": required field must be an array"}
	}
	if len(array) == 0 {
		return []string{path + ": required array must contain at least one element"}
	}
	return nil
}

func validateStringArray(raw map[string]any, key string) []string {
	return validateStringArrayAtPath(raw, key, key)
}

func validateStringArrayAtPath(
	raw map[string]any,
	key string,
	path string,
) []string {
	value, exists := raw[key]
	if !exists {
		return nil
	}
	array, ok := value.([]any)
	if !ok {
		return nil
	}
	for index, item := range array {
		if _, ok := item.(string); !ok {
			return []string{fmt.Sprintf("%s[%d]: must be a string", path, index)}
		}
	}
	return nil
}

func validateSecuritySchemesContainer(raw map[string]any) []string {
	value, exists := raw["securitySchemes"]
	if !exists {
		return nil
	}
	if _, ok := value.(map[string]any); !ok {
		return []string{"securitySchemes: must be an object"}
	}
	return nil
}

func validateSignatureObjects(raw map[string]any) []string {
	value, exists := raw["signatures"]
	if !exists || value == nil {
		return nil
	}
	signatures, ok := value.([]any)
	if !ok {
		return []string{"signatures: must be an array"}
	}
	var errors []string
	for index, value := range signatures {
		path := fmt.Sprintf("signatures[%d]", index)
		object, ok := value.(map[string]any)
		if !ok {
			errors = append(errors, path+": must be an object")
			continue
		}
		errors = append(errors, validateRequiredString(object, path+".protected")...)
		errors = append(errors, validateRequiredString(object, path+".signature")...)
	}
	return errors
}

func finalPathComponent(path string) string {
	for index := len(path) - 1; index >= 0; index-- {
		if path[index] == '.' {
			return path[index+1:]
		}
	}
	return path
}

func isStringField(raw map[string]any, key string) bool {
	_, ok := raw[key].(string)
	return ok
}

func validInterfaceURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ws", "wss":
		return true
	default:
		return false
	}
}

func validHTTPURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "http") ||
		strings.EqualFold(parsed.Scheme, "https")
}
