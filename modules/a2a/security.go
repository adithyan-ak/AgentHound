package a2a

import (
	"fmt"
	"sort"
	"strings"
)

func parseV030SecuritySchemes(raw map[string]any) []SecurityScheme {
	values, ok := raw["securitySchemes"].(map[string]any)
	if !ok {
		return nil
	}
	names := sortedMapKeys(values)
	schemes := make([]SecurityScheme, 0, len(names))
	for _, name := range names {
		object, ok := values[name].(map[string]any)
		if !ok {
			schemes = append(schemes, SecurityScheme{Name: name})
			continue
		}
		scheme := SecurityScheme{
			Name:   name,
			Type:   getString(object, "type"),
			Scheme: getString(object, "scheme"),
		}
		switch strings.ToLower(scheme.Type) {
		case "apikey":
			scheme.Conformant = validAPIKeyLocation(getString(object, "in")) &&
				nonEmptyStringField(object, "name")
		case "http":
			scheme.Conformant = nonEmptyStringField(object, "scheme")
		case "oauth2":
			scheme.Conformant = validV030OAuthFlows(object["flows"])
		case "openidconnect":
			scheme.Conformant = validHTTPURL(getString(object, "openIdConnectUrl"))
		case "mutualtls":
			scheme.Conformant = true
		}
		schemes = append(schemes, scheme)
	}
	return schemes
}

func parseV10SecuritySchemes(raw map[string]any) []SecurityScheme {
	values, ok := raw["securitySchemes"].(map[string]any)
	if !ok {
		return nil
	}
	names := sortedMapKeys(values)
	schemes := make([]SecurityScheme, 0, len(names))
	for _, name := range names {
		scheme := SecurityScheme{Name: name}
		object, ok := values[name].(map[string]any)
		if !ok {
			schemes = append(schemes, scheme)
			continue
		}
		variants := 0
		if inner, exists := object["apiKeySecurityScheme"]; exists {
			variants++
			scheme.Type = "apiKey"
			value, ok := inner.(map[string]any)
			scheme.Conformant = ok &&
				validAPIKeyLocation(getString(value, "location")) &&
				nonEmptyStringField(value, "name")
		}
		if inner, exists := object["httpAuthSecurityScheme"]; exists {
			variants++
			scheme.Type = "http"
			value, ok := inner.(map[string]any)
			if ok {
				scheme.Scheme = getString(value, "scheme")
			}
			scheme.Conformant = ok && nonEmptyStringField(value, "scheme")
		}
		if inner, exists := object["oauth2SecurityScheme"]; exists {
			variants++
			scheme.Type = "oauth2"
			value, ok := inner.(map[string]any)
			scheme.Conformant = ok && validV1OAuthFlows(value["flows"])
		}
		if inner, exists := object["openIdConnectSecurityScheme"]; exists {
			variants++
			scheme.Type = "openIdConnect"
			value, ok := inner.(map[string]any)
			scheme.Conformant = ok && validHTTPURL(getString(value, "openIdConnectUrl"))
		}
		if inner, exists := object["mtlsSecurityScheme"]; exists {
			variants++
			scheme.Type = "mutualTLS"
			_, scheme.Conformant = inner.(map[string]any)
		}
		if variants != 1 {
			scheme.Conformant = false
		}
		schemes = append(schemes, scheme)
	}
	return schemes
}

func parseV030SecurityRequirements(
	raw any,
	schemes []SecurityScheme,
) ([]SecurityRequirement, bool, []string) {
	if raw == nil {
		return nil, true, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, false, []string{"security: must be an array"}
	}
	return parseSecurityRequirements(values, schemes, false, "security")
}

func parseV10SecurityRequirements(
	raw any,
	schemes []SecurityScheme,
) ([]SecurityRequirement, bool, []string) {
	if raw == nil {
		return nil, true, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, false, []string{"securityRequirements: must be an array"}
	}
	return parseSecurityRequirements(values, schemes, true, "securityRequirements")
}

func parseSecurityRequirements(
	values []any,
	schemes []SecurityScheme,
	wrapped bool,
	path string,
) ([]SecurityRequirement, bool, []string) {
	declared := make(map[string]SecurityScheme, len(schemes))
	for _, scheme := range schemes {
		declared[scheme.Name] = scheme
	}

	requirements := make([]SecurityRequirement, 0, len(values))
	var errors []string
	for index, value := range values {
		requirementPath := fmt.Sprintf("%s[%d]", path, index)
		object, ok := value.(map[string]any)
		if !ok {
			requirements = append(requirements, SecurityRequirement{})
			errors = append(errors, requirementPath+": must be an object")
			continue
		}
		schemeMap := object
		if wrapped {
			schemeMap = map[string]any{}
			rawSchemes, exists := object["schemes"]
			if !exists || rawSchemes == nil {
				// ProtoJSON omits empty maps and accepts null as an unset field.
				// Both forms represent an empty, anonymous requirement.
			} else if wrappedSchemes, ok := rawSchemes.(map[string]any); ok {
				schemeMap = wrappedSchemes
			} else {
				requirements = append(requirements, SecurityRequirement{})
				errors = append(errors, requirementPath+".schemes: must be an object")
				continue
			}
		}

		requirement := SecurityRequirement{Conformant: true}
		for _, name := range sortedMapKeys(schemeMap) {
			scopes, valid := parseRequirementScopes(schemeMap[name], wrapped)
			requirement.Schemes = append(requirement.Schemes, SecurityRequirementScheme{
				Name:   name,
				Scopes: scopes,
			})
			scheme, exists := declared[name]
			if !valid {
				requirement.Conformant = false
				errors = append(errors, requirementPath+"."+name+": scopes must be an array of strings")
			}
			if !exists {
				requirement.Conformant = false
				errors = append(errors, requirementPath+"."+name+": references an undeclared security scheme")
			} else if !scheme.Conformant {
				requirement.Conformant = false
				errors = append(errors, requirementPath+"."+name+": references a nonconformant security scheme")
			}
		}
		requirements = append(requirements, requirement)
	}
	sort.Strings(errors)
	return requirements, len(errors) == 0, errors
}

func parseRequirementScopes(value any, wrapped bool) ([]string, bool) {
	if wrapped {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		if _, exists := object["list"]; !exists {
			return nil, true
		}
		value = object["list"]
		if value == nil {
			return nil, true
		}
	}
	array, ok := value.([]any)
	if !ok {
		return nil, false
	}
	scopes := make([]string, 0, len(array))
	for _, item := range array {
		scope, ok := item.(string)
		if !ok {
			return scopes, false
		}
		scopes = append(scopes, scope)
	}
	return scopes, true
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func nonEmptyStringField(values map[string]any, key string) bool {
	value, ok := values[key].(string)
	return ok && strings.TrimSpace(value) != ""
}

func validAPIKeyLocation(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "query", "header", "cookie":
		return true
	default:
		return false
	}
}

func validV1OAuthFlows(raw any) bool {
	flows, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	variants := 0
	valid := false
	for name, value := range flows {
		object, ok := value.(map[string]any)
		if !ok {
			continue
		}
		switch name {
		case "authorizationCode":
			variants++
			valid = validHTTPURL(getString(object, "authorizationUrl")) &&
				validHTTPURL(getString(object, "tokenUrl")) &&
				validOAuthScopes(object["scopes"])
		case "clientCredentials":
			variants++
			valid = validHTTPURL(getString(object, "tokenUrl")) &&
				validOAuthScopes(object["scopes"])
		case "implicit":
			variants++
			valid = validHTTPURL(getString(object, "authorizationUrl")) &&
				validOAuthScopes(object["scopes"])
		case "password":
			variants++
			valid = validHTTPURL(getString(object, "tokenUrl")) &&
				validOAuthScopes(object["scopes"])
		case "deviceCode":
			variants++
			valid = validHTTPURL(getString(object, "deviceAuthorizationUrl")) &&
				validHTTPURL(getString(object, "tokenUrl")) &&
				validOAuthScopes(object["scopes"])
		}
	}
	return variants == 1 && valid
}

func validV030OAuthFlows(raw any) bool {
	flows, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	found := false
	for name, value := range flows {
		if strings.HasPrefix(strings.ToLower(name), "x-") {
			continue
		}
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		found = true
		var valid bool
		switch name {
		case "authorizationCode":
			valid = validHTTPURL(getString(object, "authorizationUrl")) &&
				validHTTPURL(getString(object, "tokenUrl")) &&
				validOAuthScopes(object["scopes"])
		case "clientCredentials", "password":
			valid = validHTTPURL(getString(object, "tokenUrl")) &&
				validOAuthScopes(object["scopes"])
		case "implicit":
			valid = validHTTPURL(getString(object, "authorizationUrl")) &&
				validOAuthScopes(object["scopes"])
		default:
			return false
		}
		if !valid {
			return false
		}
	}
	return found
}

func validOAuthScopes(raw any) bool {
	scopes, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	for _, description := range scopes {
		if _, ok := description.(string); !ok {
			return false
		}
	}
	return true
}

func securitySchemeConformanceErrors(schemes []SecurityScheme) []string {
	var errors []string
	for _, scheme := range schemes {
		if !scheme.Conformant {
			errors = append(
				errors,
				"securitySchemes."+scheme.Name+": scheme is nonconformant",
			)
		}
	}
	return errors
}
