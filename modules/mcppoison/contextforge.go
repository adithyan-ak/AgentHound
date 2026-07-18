package mcppoison

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/adithyan-ak/agenthound/modules/mcp"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/campaign"
)

const (
	contextForgeMaxRequestBytes  int64 = 1 << 18
	contextForgeMaxResponseBytes int64 = 1 << 20
	contextForgeResponseHeadroom int64 = 4 << 10
	contextForgeTimeout                = 30 * time.Second
)

type contextForgeTool struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Version           int64  `json:"version"`
	ModifiedUserAgent string `json:"modifiedUserAgent,omitempty"`
	OwnerEmail        string `json:"ownerEmail,omitempty"`
	TeamID            string `json:"teamId,omitempty"`
	WireSize          int    `json:"-"`
}

func (t *contextForgeTool) UnmarshalJSON(data []byte) error {
	t.WireSize = len(data)
	type wireTool struct {
		ID                json.RawMessage `json:"id"`
		Name              json.RawMessage `json:"name"`
		Description       json.RawMessage `json:"description"`
		Version           json.RawMessage `json:"version"`
		ModifiedUserAgent json.RawMessage `json:"modifiedUserAgent"`
		OwnerEmail        json.RawMessage `json:"ownerEmail"`
		TeamID            json.RawMessage `json:"teamId"`
	}
	var raw wireTool
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	if t.ID, err = requiredJSONString(raw.ID, "id"); err != nil {
		return err
	}
	if t.Name, err = requiredJSONString(raw.Name, "name"); err != nil {
		return err
	}
	if t.Description, err = requiredJSONString(raw.Description, "description"); err != nil {
		return err
	}
	if len(raw.Version) == 0 || bytes.Equal(raw.Version, []byte("null")) {
		return errors.New("version is required")
	}
	var version json.Number
	if err := json.Unmarshal(raw.Version, &version); err != nil {
		return errors.New("version must be an integer")
	}
	parsed, err := version.Int64()
	if err != nil || parsed < 1 {
		return errors.New("version must be a positive integer")
	}
	t.Version = parsed
	if t.ModifiedUserAgent, err = optionalJSONString(raw.ModifiedUserAgent, "modifiedUserAgent"); err != nil {
		return err
	}
	if t.OwnerEmail, err = optionalJSONString(raw.OwnerEmail, "ownerEmail"); err != nil {
		return err
	}
	if t.TeamID, err = optionalJSONString(raw.TeamID, "teamId"); err != nil {
		return err
	}
	if _, err := canonicalUUID(t.ID, "tool id"); err != nil {
		return err
	}
	if t.TeamID != "" {
		if _, err := canonicalUUID(t.TeamID, "tool team_id"); err != nil {
			return err
		}
	}
	return nil
}

type contextForgeServer struct {
	ID                string   `json:"id"`
	TeamID            string   `json:"teamId,omitempty"`
	OwnerEmail        string   `json:"ownerEmail,omitempty"`
	AssociatedToolIDs []string `json:"associatedToolIds"`
}

type contextForgePrincipal struct {
	Email    string `json:"email"`
	IsAdmin  bool   `json:"is_admin"`
	IsActive bool   `json:"is_active"`
}

func (s *contextForgeServer) UnmarshalJSON(data []byte) error {
	type wireServer struct {
		ID                json.RawMessage `json:"id"`
		TeamID            json.RawMessage `json:"teamId"`
		OwnerEmail        json.RawMessage `json:"ownerEmail"`
		AssociatedToolIDs json.RawMessage `json:"associatedToolIds"`
	}
	var raw wireServer
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	if s.ID, err = requiredJSONString(raw.ID, "id"); err != nil {
		return err
	}
	if _, err := canonicalUUID(s.ID, "server id"); err != nil {
		return err
	}
	if s.TeamID, err = optionalJSONString(raw.TeamID, "teamId"); err != nil {
		return err
	}
	if s.TeamID != "" {
		if _, err := canonicalUUID(s.TeamID, "server team_id"); err != nil {
			return err
		}
	}
	if s.OwnerEmail, err = optionalJSONString(raw.OwnerEmail, "ownerEmail"); err != nil {
		return err
	}
	if len(raw.AssociatedToolIDs) == 0 || bytes.Equal(raw.AssociatedToolIDs, []byte("null")) {
		return errors.New("associatedToolIds is required")
	}
	if err := json.Unmarshal(raw.AssociatedToolIDs, &s.AssociatedToolIDs); err != nil {
		return errors.New("associatedToolIds must be an array of ContextForge UUID strings")
	}
	seen := make(map[string]struct{}, len(s.AssociatedToolIDs))
	for _, id := range s.AssociatedToolIDs {
		if _, err := canonicalUUID(id, "associated tool id"); err != nil {
			return err
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("associated tool id %q is duplicated", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func requiredJSONString(raw json.RawMessage, field string) (string, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", fmt.Errorf("%s is required and must be a string", field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s must be a string", field)
	}
	return value, nil
}

func optionalJSONString(raw json.RawMessage, field string) (string, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s must be a string or null", field)
	}
	return value, nil
}

type contextForgeConfig struct {
	MCPURL         string
	ManagementBase string
	ServerID       string
	ToolName       string
	Insecure       bool
}

// ValidateContextForgeEndpoints validates the provider URL contract without
// opening a connection. It is shared by direct poisoning and campaign planning.
func ValidateContextForgeEndpoints(mcpURL, managementBase string) error {
	_, _, derivedBase, err := parseContextForgeMCPURL(mcpURL)
	if err != nil {
		return fmt.Errorf("invalid ContextForge MCP URL: %w", err)
	}
	managementBase = strings.TrimSpace(managementBase)
	if managementBase == "" {
		managementBase = derivedBase
	}
	if _, err := validateManagementBase(managementBase); err != nil {
		return fmt.Errorf("invalid ContextForge management URL: %w", err)
	}
	return nil
}

func parseContextForgeConfig(t action.Target, toolName string, extras map[string]any) (contextForgeConfig, error) {
	adapter, _ := extras["adapter"].(string)
	if strings.TrimSpace(adapter) != action.ContextForgeProfile {
		return contextForgeConfig{}, fmt.Errorf("mcp poison: --adapter must be %q because MCP defines no mutation endpoint", action.ContextForgeProfile)
	}
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return contextForgeConfig{}, errors.New("mcp poison: --target-id is required")
	}
	mcpURL, serverID, derivedBase, err := parseContextForgeMCPURL(targetURL(t))
	if err != nil {
		return contextForgeConfig{}, fmt.Errorf("mcp poison: invalid ContextForge MCP URL: %w", err)
	}
	managementBase, _ := extras["management-url"].(string)
	managementBase = strings.TrimSpace(managementBase)
	if managementBase == "" {
		managementBase = derivedBase
	}
	managementBase, err = validateManagementBase(managementBase)
	if err != nil {
		return contextForgeConfig{}, fmt.Errorf("mcp poison: invalid --management-url: %w", err)
	}
	insecure, _ := extras["insecure"].(bool)
	return contextForgeConfig{
		MCPURL: mcpURL, ManagementBase: managementBase, ServerID: serverID,
		ToolName: toolName, Insecure: insecure,
	}, nil
}

func targetURL(t action.Target) string {
	if explicit := strings.TrimSpace(t.Meta["url"]); explicit != "" {
		return explicit
	}
	return strings.TrimSpace(t.Address)
}

func parseContextForgeMCPURL(raw string) (mcpURL, serverID, managementBase string, err error) {
	u, err := parseAbsoluteHTTPURL(raw)
	if err != nil {
		return "", "", "", err
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 3 || parts[len(parts)-3] != "servers" || parts[len(parts)-1] != "mcp" {
		return "", "", "", errors.New("path must end in /servers/{server-uuid}/mcp")
	}
	decoded, err := url.PathUnescape(parts[len(parts)-2])
	if err != nil {
		return "", "", "", errors.New("server UUID path segment is malformed")
	}
	serverID, err = canonicalUUID(decoded, "server id")
	if err != nil {
		return "", "", "", err
	}
	if parts[len(parts)-2] != serverID {
		return "", "", "", errors.New("server UUID path segment must be unescaped canonical text")
	}
	prefixParts := parts[:len(parts)-3]
	base := *u
	if len(prefixParts) == 0 {
		base.Path = ""
	} else {
		for _, part := range prefixParts {
			if part == "" {
				return "", "", "", errors.New("management path prefix must not contain empty segments")
			}
			value, unescapeErr := url.PathUnescape(part)
			if unescapeErr != nil || value != part || part == "." || part == ".." {
				return "", "", "", errors.New("management path prefix must use unescaped non-dot segments")
			}
		}
		base.Path = "/" + strings.Join(prefixParts, "/")
	}
	base.RawPath = ""
	return u.String(), serverID, strings.TrimSuffix(base.String(), "/"), nil
}

func extractContextForgeServerID(raw string) (string, error) {
	_, serverID, _, err := parseContextForgeMCPURL(raw)
	return serverID, err
}

func validateManagementBase(raw string) (string, error) {
	u, err := parseAbsoluteHTTPURL(raw)
	if err != nil {
		return "", err
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	if path != "" {
		for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			if part == "" {
				return "", errors.New("management base path must not contain empty segments")
			}
			value, unescapeErr := url.PathUnescape(part)
			if unescapeErr != nil || value != part || part == "." || part == ".." {
				return "", errors.New("management base path must use unescaped non-dot segments")
			}
		}
	}
	if path == "/v1" || strings.HasSuffix(path, "/v1") {
		return "", errors.New("base URL must omit /v1; AgentHound appends the fixed ContextForge API paths")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

func parseAbsoluteHTTPURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("URL must be an absolute HTTP(S) endpoint")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("URL scheme must be http or https")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("userinfo, query, and fragment are prohibited")
	}
	return u, nil
}

func canonicalUUID(value, field string) (string, error) {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return "", fmt.Errorf("%s must be a canonical lowercase 32-hex ContextForge UUID", field)
	}
	if strings.ReplaceAll(parsed.String(), "-", "") != value {
		return "", fmt.Errorf("%s must be a canonical lowercase 32-hex ContextForge UUID", field)
	}
	return value, nil
}

type contextForgeClient struct {
	base   string
	client *http.Client
}

type contextForgeContractError struct{ err error }

func (e contextForgeContractError) Error() string { return e.err.Error() }
func (e contextForgeContractError) Unwrap() error { return e.err }

type contextForgeResponseLossError struct{ err error }

func (e contextForgeResponseLossError) Error() string { return e.err.Error() }
func (e contextForgeResponseLossError) Unwrap() error { return e.err }

func isContextForgeContractError(err error) bool {
	var contractErr contextForgeContractError
	return errors.As(err, &contractErr)
}

type contextForgeStatusError struct {
	method string
	path   string
	status int
}

func (e contextForgeStatusError) Error() string {
	return fmt.Sprintf("ContextForge %s %s returned status %d; expected 200", e.method, e.path, e.status)
}

func isDefinitiveWriteRejection(err error) bool {
	var statusErr contextForgeStatusError
	return errors.As(err, &statusErr) && statusErr.status >= http.StatusBadRequest && statusErr.status < http.StatusInternalServerError
}

func newContextForgeClient(base, token string, insecure bool, timeout time.Duration) (*contextForgeClient, error) {
	validated, err := validateManagementBase(base)
	if err != nil {
		return nil, err
	}
	origin, err := campaign.ParseHTTPOrigin(validated)
	if err != nil {
		return nil, errors.New("management URL has an invalid HTTP origin")
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is not configurable")
	}
	transport := defaultTransport.Clone()
	if insecure {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
	}
	bound := contextForgeCredentialTransport{
		base: transport, origin: origin, authorization: "Bearer " + token,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: campaign.CountingTransport{Base: bound},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("ContextForge redirect rejected")
		},
	}
	return &contextForgeClient{base: validated, client: client}, nil
}

type contextForgeCredentialTransport struct {
	base          http.RoundTripper
	origin        campaign.HTTPOrigin
	authorization string
}

func (t contextForgeCredentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	if t.origin.Matches(req.URL) {
		cloned.Header.Set("Authorization", t.authorization)
	} else {
		cloned.Header.Del("Authorization")
	}
	return t.base.RoundTrip(cloned)
}

func (c *contextForgeClient) getServer(ctx context.Context, serverID string) (contextForgeServer, error) {
	var server contextForgeServer
	err := c.doJSON(ctx, http.MethodGet, serverReadPath(serverID), nil, &server)
	return server, err
}

func (c *contextForgeClient) getPrincipal(ctx context.Context) (contextForgePrincipal, error) {
	var principal contextForgePrincipal
	if err := c.doJSON(ctx, http.MethodGet, identityReadPath(), nil, &principal); err != nil {
		return contextForgePrincipal{}, err
	}
	principal.Email = strings.TrimSpace(principal.Email)
	if principal.Email == "" {
		return contextForgePrincipal{}, errors.New("ContextForge identity response omitted email")
	}
	if !principal.IsActive {
		return contextForgePrincipal{}, errors.New("ContextForge identity is not active")
	}
	return principal, nil
}

func (c *contextForgeClient) getPermissions(ctx context.Context, teamID string) (map[string]struct{}, error) {
	var values []string
	if err := c.doJSON(ctx, http.MethodGet, permissionsReadPath(teamID), nil, &values); err != nil {
		return nil, err
	}
	permissions := make(map[string]struct{}, len(values))
	for _, permission := range values {
		permission = strings.TrimSpace(permission)
		if permission == "" || strings.ContainsAny(permission, "\r\n") {
			return nil, errors.New("ContextForge effective permissions contain an invalid entry")
		}
		permissions[permission] = struct{}{}
	}
	return permissions, nil
}

func (c *contextForgeClient) listServerTools(ctx context.Context, serverID string) ([]contextForgeTool, error) {
	var tools []contextForgeTool
	err := c.doJSON(ctx, http.MethodGet, associationReadPath(serverID), nil, &tools)
	return tools, err
}

func (c *contextForgeClient) getTool(ctx context.Context, toolID string) (contextForgeTool, error) {
	var tool contextForgeTool
	err := c.doJSON(ctx, http.MethodGet, recordReadPath(toolID), nil, &tool)
	return tool, err
}

func (c *contextForgeClient) putDescription(ctx context.Context, toolID, description, userAgent string) (contextForgeTool, error) {
	body, err := marshalDescriptionBody(description)
	if err != nil {
		return contextForgeTool{}, err
	}
	var tool contextForgeTool
	err = c.doJSONWithUserAgent(ctx, http.MethodPut, writePath(toolID), body, userAgent, &tool)
	return tool, err
}

func marshalDescriptionBody(description string) ([]byte, error) {
	body, err := json.Marshal(struct {
		Description string `json:"description"`
	}{Description: description})
	if err != nil {
		return nil, fmt.Errorf("encode ContextForge description body: %w", err)
	}
	if int64(len(body)) > contextForgeMaxRequestBytes {
		return nil, fmt.Errorf("ContextForge description request exceeds %d bytes", contextForgeMaxRequestBytes)
	}
	return body, nil
}

func (c *contextForgeClient) doJSON(ctx context.Context, method, path string, body []byte, out any) error {
	return c.doJSONWithUserAgent(ctx, method, path, body, "", out)
}

func (c *contextForgeClient) doJSONWithUserAgent(ctx context.Context, method, path string, body []byte, userAgent string, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, contextForgeMaxResponseBytes))
		return contextForgeContractError{contextForgeStatusError{method: method, path: path, status: resp.StatusCode}}
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return contextForgeContractError{fmt.Errorf("ContextForge %s %s returned unexpected content type %q", method, path, resp.Header.Get("Content-Type"))}
	}
	if resp.ContentLength > contextForgeMaxResponseBytes {
		return contextForgeContractError{fmt.Errorf("ContextForge %s %s response exceeds %d bytes", method, path, contextForgeMaxResponseBytes)}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, contextForgeMaxResponseBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > contextForgeMaxResponseBytes {
		return contextForgeContractError{fmt.Errorf("ContextForge %s %s response exceeds %d bytes", method, path, contextForgeMaxResponseBytes)}
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return contextForgeResponseLossError{fmt.Errorf("ContextForge %s %s returned an empty JSON body", method, path)}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return contextForgeContractError{fmt.Errorf("decode ContextForge %s %s JSON: %w", method, path, err)}
	}
	return nil
}

func identityReadPath() string { return "/v1/auth/email/me" }
func permissionsReadPath(teamID string) string {
	path := "/v1/rbac/my/permissions"
	if teamID != "" {
		path += "?team_id=" + teamID
	}
	return path
}
func serverReadPath(serverID string) string      { return "/v1/servers/" + serverID }
func associationReadPath(serverID string) string { return serverReadPath(serverID) + "/tools" }
func recordReadPath(toolID string) string        { return "/v1/tools/" + toolID }
func writePath(toolID string) string             { return recordReadPath(toolID) }

type contextForgeClaims struct {
	Permissions map[string]struct{}
	TokenUse    string
	APIIdentity string
}

func resolveContextForgeToken(mcpURL, managementBase string) (string, error) {
	token := strings.TrimSpace(os.Getenv("AGENTHOUND_CONTEXTFORGE_TOKEN"))
	if token != "" {
		if strings.ContainsAny(token, "\r\n") {
			return "", errors.New("AGENTHOUND_CONTEXTFORGE_TOKEN contains prohibited control characters")
		}
		return token, nil
	}
	mcpOrigin, err := campaign.ParseHTTPOrigin(mcpURL)
	if err != nil {
		return "", errors.New("cannot compare MCP and ContextForge credential origins")
	}
	managementURL, err := url.Parse(managementBase)
	if err != nil || !mcpOrigin.Matches(managementURL) {
		return "", errors.New("AGENTHOUND_CONTEXTFORGE_TOKEN is required when the management URL has a different origin from the MCP URL")
	}
	authorization, err := resolveMCPAuthorization(mcpURL)
	if err != nil {
		return "", fmt.Errorf("resolve same-origin MCP credential fallback: %w", err)
	}
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.ContainsAny(parts[1], "\r\n") {
		return "", errors.New("AGENTHOUND_CONTEXTFORGE_TOKEN is required unless same-origin MCP authentication is a Bearer token")
	}
	return parts[1], nil
}

func parseContextForgeClaims(token string) (contextForgeClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return contextForgeClaims{}, errors.New("token must be a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return contextForgeClaims{}, errors.New("JWT payload is not base64url")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return contextForgeClaims{}, errors.New("JWT payload is not a JSON object")
	}
	claims := contextForgeClaims{Permissions: make(map[string]struct{})}
	if err := json.Unmarshal(raw["token_use"], &claims.TokenUse); err != nil ||
		(claims.TokenUse != "session" && claims.TokenUse != "api") {
		return contextForgeClaims{}, errors.New("JWT token_use must be session or api")
	}
	scopesRaw := raw["scopes"]
	if len(scopesRaw) == 0 || bytes.Equal(scopesRaw, []byte("null")) {
		return contextForgeClaims{}, errors.New("JWT scopes are required to prove management permissions")
	}
	var scopes struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(scopesRaw, &scopes); err != nil {
		return contextForgeClaims{}, errors.New("JWT scopes must be an object")
	}
	for _, permission := range scopes.Permissions {
		permission = strings.TrimSpace(permission)
		if permission == "" || strings.ContainsAny(permission, "\r\n") {
			return contextForgeClaims{}, errors.New("JWT permission scope contains an invalid entry")
		}
		claims.Permissions[permission] = struct{}{}
	}
	if claims.TokenUse == "api" {
		if err := json.Unmarshal(raw["sub"], &claims.APIIdentity); err != nil || strings.TrimSpace(claims.APIIdentity) == "" {
			return contextForgeClaims{}, errors.New("API-token JWT sub must contain the owner email")
		}
		claims.APIIdentity = strings.TrimSpace(claims.APIIdentity)
		if userRaw := raw["user"]; len(userRaw) != 0 && !bytes.Equal(userRaw, []byte("null")) {
			var user struct {
				Email string `json:"email"`
			}
			if err := json.Unmarshal(userRaw, &user); err != nil {
				return contextForgeClaims{}, errors.New("API-token JWT user must be an object")
			}
			if user.Email != "" && !strings.EqualFold(user.Email, claims.APIIdentity) {
				return contextForgeClaims{}, errors.New("API-token JWT user email does not match sub")
			}
		}
	}
	return claims, nil
}

func acceptedContextForgeClaims(token string) (contextForgeClaims, error) {
	claims, err := parseContextForgeClaims(token)
	if err != nil {
		return contextForgeClaims{}, fmt.Errorf("decode AGENTHOUND_CONTEXTFORGE_TOKEN claims: %w", err)
	}
	return claims, nil
}

func (c contextForgeClaims) authorizePermissions(ctx context.Context, client *contextForgeClient, server contextForgeServer, tool contextForgeTool, principal contextForgePrincipal) error {
	if len(c.Permissions) != 0 {
		if _, unrestricted := c.Permissions["*"]; !unrestricted {
			return errors.New("ContextForge token has an exact permission ceiling that blocks proof of provider RBAC; use a session token or an API token with an empty or wildcard permission ceiling")
		}
	}
	if principal.IsAdmin {
		return nil
	}
	serverPermissions, err := client.getPermissions(ctx, server.TeamID)
	if err != nil {
		return fmt.Errorf("resolve ContextForge server-team effective permissions: %w", err)
	}
	toolPermissions := serverPermissions
	if tool.TeamID != server.TeamID {
		toolPermissions, err = client.getPermissions(ctx, tool.TeamID)
		if err != nil {
			return fmt.Errorf("resolve ContextForge tool-team effective permissions: %w", err)
		}
	}
	if !hasPermission(serverPermissions, "servers.read") {
		return errors.New("ContextForge effective RBAC lacks required servers.read permission in the server team context")
	}
	for _, required := range []string{"tools.read", "tools.update"} {
		if !hasPermission(toolPermissions, required) {
			return fmt.Errorf("ContextForge effective RBAC lacks required %s permission in the tool team context", required)
		}
	}
	return nil
}

func hasPermission(permissions map[string]struct{}, required string) bool {
	_, wildcard := permissions["*"]
	_, exact := permissions[required]
	return wildcard || exact
}

func (c contextForgeClaims) resolvePrincipal(ctx context.Context, client *contextForgeClient) (contextForgePrincipal, error) {
	principal, err := client.getPrincipal(ctx)
	if err != nil {
		return contextForgePrincipal{}, err
	}
	if c.TokenUse == "api" && (c.APIIdentity == "" || !strings.EqualFold(c.APIIdentity, principal.Email)) {
		return contextForgePrincipal{}, errors.New("ContextForge API-token identity does not match the provider profile")
	}
	if c.TokenUse != "api" && c.TokenUse != "session" {
		return contextForgePrincipal{}, errors.New("ContextForge token identity cannot be resolved")
	}
	return principal, nil
}

func (p contextForgePrincipal) authorizeOwnership(server contextForgeServer, tool contextForgeTool) error {
	if p.IsAdmin {
		return nil
	}
	if server.OwnerEmail == "" || !strings.EqualFold(server.OwnerEmail, p.Email) {
		return errors.New("ContextForge server direct ownership cannot be proven from the authenticated profile")
	}
	if tool.OwnerEmail == "" || !strings.EqualFold(tool.OwnerEmail, p.Email) {
		return errors.New("ContextForge tool direct ownership cannot be proven from the authenticated profile")
	}
	return nil
}

func resolveMCPAuthorization(targetURL string) (string, error) {
	if token := strings.TrimSpace(os.Getenv("AGENTHOUND_MCP_TOKEN")); token != "" {
		if strings.ContainsAny(token, "\r\n") {
			return "", errors.New("AGENTHOUND_MCP_TOKEN contains prohibited control characters")
		}
		return "Bearer " + token, nil
	}
	header, err := mcp.ResolveAuthorizationHeader(targetURL)
	if err != nil {
		return "", err
	}
	return header, nil
}
