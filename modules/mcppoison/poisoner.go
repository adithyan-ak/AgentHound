// Package mcppoison implements a provider-specific, reversible ContextForge
// MCP tool-description mutation. MCP itself defines observation, not metadata
// management; no generic or guessed update endpoint is exposed here.
package mcppoison

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/adithyan-ak/agenthound/modules/mcp"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

const DefaultProbeTimeout = contextForgeTimeout

var (
	ErrNoMutation              = errors.New("mcp poison: requested mutation would not change target")
	ErrRevertIndeterminate     = action.ErrRevertIndeterminate
	ErrRevertConflict          = action.ErrRevertConflict
	ErrRevertPartiallyVerified = action.ErrRevertPartiallyVerified
)

type Poisoner struct {
	stateful     module.StatefulModule
	campaign     bool
	pollInterval time.Duration
	pollAttempts int
}

func New() *Poisoner {
	return &Poisoner{
		stateful:     module.NewFileStatefulModule("mcp.poison"),
		pollInterval: 250 * time.Millisecond,
		pollAttempts: 12,
	}
}

func NewForCampaign() *Poisoner {
	p := New()
	p.campaign = true
	return p
}

func (p *Poisoner) Stateful() module.StatefulModule { return p.stateful }

func (p *Poisoner) SetStateful(stateful module.StatefulModule) { p.stateful = stateful }

func (*Poisoner) RegisterFlags(fs *pflag.FlagSet) {
	fs.String("adapter", "", `Management adapter; MCP tool-description mutation requires "contextforge".`)
	fs.String("management-url", "", "Optional ContextForge deployment base; derived from a server-scoped MCP URL when omitted.")
	fs.Bool("insecure", false, "Skip TLS verification for MCP and ContextForge endpoints.")
}

// Observation is the dual-surface state used by the standalone poison command
// and reversible round-trip scenario.
type Observation struct {
	Associated                  bool
	MCPObserved                 bool
	ManagementObserved          bool
	MCPDescription              string
	ManagementDescription       string
	ManagementVersion           int64
	ManagementModifiedUserAgent string
	ToolID                      string
	ServerID                    string
}

type preflightState struct {
	config contextForgeConfig
	client *contextForgeClient
	claims contextForgeClaims
	actor  contextForgePrincipal
	server contextForgeServer
	tool   contextForgeTool
	mcp    mcp.ToolObservation
}

func (p *Poisoner) Poison(ctx context.Context, target action.Target, payload action.PoisonPayload) (*action.PoisonReceipt, error) {
	if payload.InjectionContent == "" {
		return nil, errors.New("mcp poison: --inject or --inject-file is required")
	}
	if strings.TrimSpace(payload.EngagementID) == "" {
		return nil, errors.New("mcp poison: --engagement-id is required")
	}
	mode := payload.Mode
	if mode == "" {
		mode = "replace"
	}
	if mode != "replace" && mode != "append" && mode != "prepend" {
		return nil, fmt.Errorf("mcp poison: unsupported --mode %q (use replace/append/prepend)", mode)
	}
	config, err := parseContextForgeConfig(target, payload.TargetID, payload.Extras)
	if err != nil {
		return nil, err
	}
	state, err := p.preflight(ctx, config)
	if err != nil {
		return nil, err
	}
	updated := composeContent(state.tool.Description, payload.InjectionContent, mode)
	if updated == state.tool.Description {
		return nil, ErrNoMutation
	}
	finalState, err := p.preflight(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("mcp poison: final pre-write preflight failed: %w", err)
	}
	if !samePreflightState(state, finalState) {
		return nil, errors.New("mcp poison: target changed between preflights; refusing to persist a receipt or write")
	}
	state = finalState
	updated = composeContent(state.tool.Description, payload.InjectionContent, mode)
	body, err := marshalDescriptionBody(updated)
	if err != nil {
		return nil, fmt.Errorf("mcp poison: outbound description rejected before receipt persistence: %w", err)
	}
	if _, err := marshalDescriptionBody(state.tool.Description); err != nil {
		return nil, fmt.Errorf("mcp poison: original description cannot be safely restored within the fixed request bound: %w", err)
	}
	if int64(state.tool.WireSize)+contextForgeResponseHeadroom > contextForgeMaxResponseBytes {
		return nil, fmt.Errorf("mcp poison: exact ContextForge tool record leaves insufficient response headroom for a safely observable restoration (record=%d, limit=%d)", state.tool.WireSize, contextForgeMaxResponseBytes)
	}
	if int64(state.tool.WireSize)+int64(len(body))+contextForgeResponseHeadroom > contextForgeMaxResponseBytes {
		return nil, fmt.Errorf("mcp poison: exact ContextForge tool record leaves insufficient response headroom for a safely observable update (record=%d, request=%d, limit=%d)", state.tool.WireSize, len(body), contextForgeMaxResponseBytes)
	}
	if hasAgentHoundForwardAttribution(state.tool.ModifiedUserAgent) {
		return nil, errors.New("mcp poison: the exact ContextForge row is already attributed to an unrestored AgentHound forward operation; recover that receipt before another mutation")
	}
	if err := p.rejectRepeatedEngagementTarget(payload.EngagementID, state); err != nil {
		return nil, err
	}
	receipt, err := newContextForgeReceipt(target, payload, mode, state, updated)
	if err != nil {
		return nil, err
	}
	if payload.DryRun {
		return receipt, nil
	}
	if _, err := p.stateful.WriteReceipt(payload.EngagementID, receipt); err != nil {
		return nil, fmt.Errorf("persist receipt before ContextForge mutation: %w", err)
	}

	contract := receipt.ContextForge
	response, responseErr := state.client.putDescription(
		ctx, state.tool.ID, updated, contract.Management.ForwardUserAgent,
	)
	if responseErr == nil {
		if err := validateWriteResponse(response, state.tool, updated, contract.Management.ForwardUserAgent); err != nil {
			responseErr = err
		}
	}
	current, reconcileErr := p.pollManagement(ctx, state.client, state.tool.ID, func(tool contextForgeTool) bool {
		return forwardWriteOwned(tool, state.tool, contract.Management.ForwardUserAgent)
	})
	if reconcileErr != nil {
		if responseErr != nil && isDefinitiveWriteRejection(responseErr) && current == state.tool {
			_, associated, associationErr := p.readAssociationStatus(ctx, state.client, config.ServerID, config.ToolName, current)
			_, mcpErr := p.pollMCP(ctx, config, state.tool.Description)
			if associationErr == nil && associated && mcpErr == nil {
				return receipt, fmt.Errorf("ContextForge rejected the write and bounded read-back confirmed the target remained unchanged: %w", responseErr)
			}
		}
		if responseErr != nil {
			return receipt, fmt.Errorf("ContextForge write response invalid (%v) and committed state is %w", responseErr, action.ErrRevertIndeterminate)
		}
		return receipt, fmt.Errorf("ContextForge write could not be reconciled; state is %w: %v", action.ErrRevertIndeterminate, reconcileErr)
	}
	if current.Description != updated {
		cleanupErr := p.cleanupOwnedForward(ctx, state, receipt, false)
		if cleanupErr != nil {
			return receipt, fmt.Errorf("ContextForge normalized the requested description and automatic cleanup failed: %w; state is %w", cleanupErr, action.ErrRevertIndeterminate)
		}
		return receipt, errors.New("ContextForge normalized the requested description; AgentHound restored the original without repeating the forward write")
	}
	if isContextForgeContractError(responseErr) {
		cleanupErr := p.cleanupOwnedForward(ctx, state, receipt, false)
		if cleanupErr != nil {
			return receipt, fmt.Errorf("ContextForge write response violated the fixed contract (%v) and automatic cleanup failed: %w; state is %w", responseErr, cleanupErr, action.ErrRevertIndeterminate)
		}
		return receipt, fmt.Errorf("ContextForge write response violated the fixed contract; AgentHound restored the original: %w", responseErr)
	}
	_, associated, associationErr := p.readAssociationStatus(ctx, state.client, config.ServerID, config.ToolName, current)
	if associationErr != nil {
		cleanupErr := p.cleanupOwnedForward(ctx, state, receipt, false)
		if cleanupErr != nil {
			return receipt, fmt.Errorf("post-write ContextForge association verification failed (%v) and automatic cleanup failed: %w; state is %w", associationErr, cleanupErr, action.ErrRevertIndeterminate)
		}
		return receipt, fmt.Errorf("post-write ContextForge association verification failed; AgentHound restored the original after dual-surface verification: %v", associationErr)
	}
	if !associated {
		cleanupErr := p.cleanupOwnedForward(ctx, state, receipt, true)
		if cleanupErr != nil {
			return receipt, fmt.Errorf("post-write ContextForge association detached and automatic cleanup failed: %w; state is %w", cleanupErr, action.ErrRevertIndeterminate)
		}
		return receipt, errors.New("post-write ContextForge association detached; AgentHound restored the management row, but MCP verification was unavailable")
	}
	if _, err := p.pollMCP(ctx, config, updated); err != nil {
		cleanupErr := p.cleanupOwnedForward(ctx, state, receipt, false)
		if cleanupErr != nil {
			return receipt, fmt.Errorf("post-write MCP observation failed (%v) and automatic cleanup failed: %w; state is %w", err, cleanupErr, action.ErrRevertIndeterminate)
		}
		return receipt, fmt.Errorf("post-write MCP observation failed; AgentHound restored the original: %w", err)
	}
	slog.Info("mcp poison applied through ContextForge",
		"target_id", config.ToolName,
		"server_id", config.ServerID,
		"engagement_id", payload.EngagementID,
	)
	return receipt, nil
}

func samePreflightState(first, second preflightState) bool {
	return first.config == second.config &&
		first.actor == second.actor &&
		first.server.ID == second.server.ID &&
		first.server.TeamID == second.server.TeamID &&
		first.server.OwnerEmail == second.server.OwnerEmail &&
		first.tool.ID == second.tool.ID &&
		first.tool.Name == second.tool.Name &&
		first.tool.Description == second.tool.Description &&
		first.tool.Version == second.tool.Version &&
		first.tool.ModifiedUserAgent == second.tool.ModifiedUserAgent &&
		first.tool.TeamID == second.tool.TeamID &&
		first.tool.OwnerEmail == second.tool.OwnerEmail &&
		first.mcp == second.mcp
}

type revertState struct {
	server      contextForgeServer
	associated  bool
	tool        contextForgeTool
	mcp         mcp.ToolObservation
	mcpObserved bool
}

func (p *Poisoner) stableRevertState(
	ctx context.Context,
	client *contextForgeClient,
	config contextForgeConfig,
	contract *action.ContextForgeToolDescriptionReceipt,
	token string,
) (revertState, error) {
	state, err := p.readRevertState(ctx, client, config, contract.Management.ToolID)
	if err != nil {
		if errors.Is(err, action.ErrRevertConflict) {
			return revertState{}, fmt.Errorf("mcp poison revert: exact management identity changed (not writing): %w", err)
		}
		return revertState{}, fmt.Errorf("mcp poison revert: re-read failed; state %w (not writing): %v", action.ErrRevertIndeterminate, err)
	}
	claims, err := acceptedContextForgeClaims(token)
	if err != nil {
		return revertState{}, fmt.Errorf("mcp poison revert: accepted token claims are invalid: %w", err)
	}
	principal, err := claims.resolvePrincipal(ctx, client)
	if err != nil {
		return revertState{}, fmt.Errorf("mcp poison revert: authenticated identity preflight failed (not writing): %w", err)
	}
	if err := authorizeRevertState(ctx, client, state, contract, claims, principal); err != nil {
		return revertState{}, err
	}
	original := contract.Management.OriginalDescription
	for attempt := 0; ; attempt++ {
		managementOriginal := state.tool.Description == original
		surfacesAgree := !state.associated ||
			(state.mcpObserved && state.mcp.Description == state.tool.Description)
		if !managementOriginal && surfacesAgree {
			return state, nil
		}
		if attempt+1 >= p.attempts() {
			if managementOriginal && surfacesAgree {
				return state, nil
			}
			return revertState{}, fmt.Errorf("mcp poison revert: management and MCP did not converge during bounded polling; state %w (not writing)", action.ErrRevertIndeterminate)
		}
		if err := p.waitPoll(ctx, attempt, p.attempts()); err != nil {
			return revertState{}, fmt.Errorf("mcp poison revert: stabilization polling failed; state %w: %v", action.ErrRevertIndeterminate, err)
		}
		state, err = p.readRevertState(ctx, client, config, contract.Management.ToolID)
		if err != nil {
			if errors.Is(err, action.ErrRevertConflict) {
				return revertState{}, fmt.Errorf("mcp poison revert: exact management identity changed during stabilization (not writing): %w", err)
			}
			return revertState{}, fmt.Errorf("mcp poison revert: stabilization re-read failed; state %w (not writing): %v", action.ErrRevertIndeterminate, err)
		}
		if err := authorizeRevertState(ctx, client, state, contract, claims, principal); err != nil {
			return revertState{}, err
		}
	}
}

func authorizeRevertState(
	ctx context.Context,
	client *contextForgeClient,
	state revertState,
	contract *action.ContextForgeToolDescriptionReceipt,
	claims contextForgeClaims,
	principal contextForgePrincipal,
) error {
	if state.server.TeamID != contract.Management.ServerTeamID || state.tool.TeamID != contract.Management.ToolTeamID {
		return fmt.Errorf("mcp poison revert: provider team identity changed; %w (not writing)", action.ErrRevertConflict)
	}
	if err := claims.authorizePermissions(ctx, client, state.server, state.tool, principal); err != nil {
		return fmt.Errorf("mcp poison revert: permission preflight failed (not writing): %w", err)
	}
	if err := principal.authorizeOwnership(state.server, state.tool); err != nil {
		return fmt.Errorf("mcp poison revert: authorization preflight failed (not writing): %w", err)
	}
	return nil
}

func (p *Poisoner) readRevertState(ctx context.Context, client *contextForgeClient, config contextForgeConfig, toolID string) (revertState, error) {
	server, associated, tool, err := p.readManagementState(ctx, client, config.ServerID, config.ToolName, toolID)
	if err != nil {
		return revertState{}, err
	}
	state := revertState{server: server, associated: associated, tool: tool}
	if !associated {
		return state, nil
	}
	observed, err := p.observeMCP(ctx, config)
	if err != nil {
		return revertState{}, err
	}
	state.mcp = observed
	state.mcpObserved = true
	return state, nil
}

func (p *Poisoner) Revert(ctx context.Context, receipt action.Receipt) error {
	r, ok := normalizeReceipt(receipt)
	if !ok {
		return fmt.Errorf("mcp poison revert: unexpected receipt type %T", receipt)
	}
	if err := validateContextForgeReceipt(r); err != nil {
		return fmt.Errorf("mcp poison revert: typed receipt rejected before network access: %w", err)
	}
	if r.DryRun {
		return nil
	}
	contract := r.ContextForge
	config := contextForgeConfig{
		MCPURL: contract.MCP.URL, ManagementBase: contract.Management.BaseURL,
		ServerID: contract.Management.ServerID, ToolName: contract.MCP.ToolName,
	}
	if insecure, _ := ctx.Value(action.RevertInsecureKey{}).(bool); insecure {
		config.Insecure = true
	}
	token, err := resolveContextForgeToken(config.MCPURL, config.ManagementBase)
	if err != nil {
		return fmt.Errorf("mcp poison revert: %w", err)
	}
	client, err := newContextForgeClient(config.ManagementBase, token, config.Insecure, p.clientTimeout())
	if err != nil {
		return fmt.Errorf("mcp poison revert: build ContextForge client: %w", err)
	}
	state, err := p.stableRevertState(ctx, client, config, contract, token)
	if err != nil {
		return err
	}
	original := contract.Management.OriginalDescription
	forwardOwned := forwardWriteOwned(state.tool, contextForgeTool{
		ID: contract.Management.ToolID, Name: contract.Management.ToolName,
		Version: contract.Management.OriginalVersion,
	}, contract.Management.ForwardUserAgent)
	if state.tool.Description == original && !forwardOwned {
		if !state.associated {
			return fmt.Errorf("mcp poison revert: management original confirmed after proven association drift; MCP verification unavailable: %w", action.ErrRevertPartiallyVerified)
		}
		return nil
	}
	if state.associated && (!state.mcpObserved || state.tool.Description != state.mcp.Description) {
		return fmt.Errorf("mcp poison revert: management and MCP descriptions diverged; state %w (not writing)", action.ErrRevertIndeterminate)
	}
	if !forwardOwned {
		return fmt.Errorf("mcp poison revert: matching non-original state is not owned by this receipt; %w (not writing)", action.ErrRevertConflict)
	}
	response, responseErr := client.putDescription(ctx, contract.Management.ToolID, original, contract.Management.RestoreUserAgent)
	if responseErr == nil {
		if err := validateRestoreResponse(response, contract); err != nil {
			responseErr = err
		}
	}
	if err := p.verifyRestored(ctx, client, config, contract, !state.associated); err != nil {
		if responseErr != nil {
			return fmt.Errorf("restore response invalid (%v) and restoration verification failed: %w", responseErr, err)
		}
		return err
	}
	if isContextForgeContractError(responseErr) {
		slog.Warn("ContextForge restore response violated the fixed contract, but independent read-back proved restoration",
			"target_id", contract.Management.ToolName,
			"tool_id", contract.Management.ToolID,
			"error", responseErr,
		)
	}
	if !state.associated {
		return fmt.Errorf("mcp poison revert: exact ContextForge row restored after proven association drift; MCP verification unavailable: %w", action.ErrRevertPartiallyVerified)
	}
	return nil
}

// Observe performs the full SDK/management identity and authorization
// preflight without mutating either surface.
func (p *Poisoner) Observe(ctx context.Context, target action.Target, targetID string, extras map[string]any) (Observation, error) {
	config, err := parseContextForgeConfig(target, targetID, extras)
	if err != nil {
		return Observation{}, err
	}
	state, err := p.preflight(ctx, config)
	if err != nil {
		return Observation{}, err
	}
	return observationFrom(state.server, state.tool, state.mcp, true), nil
}

// ObserveReceipt always addresses the immutable management tool UUID from the
// typed receipt. Association drift and MCP unavailability remain observable
// without hiding the exact management row.
func (p *Poisoner) ObserveReceipt(ctx context.Context, receipt *action.PoisonReceipt) (Observation, error) {
	if err := validateContextForgeReceipt(receipt); err != nil {
		return Observation{}, err
	}
	contract := receipt.ContextForge
	config := contextForgeConfig{
		MCPURL: contract.MCP.URL, ManagementBase: contract.Management.BaseURL,
		ServerID: contract.Management.ServerID, ToolName: contract.MCP.ToolName,
	}
	if insecure, _ := ctx.Value(action.RevertInsecureKey{}).(bool); insecure {
		config.Insecure = true
	}
	token, err := resolveContextForgeToken(config.MCPURL, config.ManagementBase)
	if err != nil {
		return Observation{}, err
	}
	client, err := newContextForgeClient(config.ManagementBase, token, config.Insecure, p.clientTimeout())
	if err != nil {
		return Observation{}, err
	}
	tool, err := client.getTool(ctx, contract.Management.ToolID)
	if err != nil {
		return Observation{}, fmt.Errorf("read receipt management tool: %w", err)
	}
	if tool.ID != contract.Management.ToolID || tool.Name != contract.Management.ToolName {
		return Observation{}, errors.New("receipt management tool identity does not match the exact ContextForge row")
	}
	observation := Observation{
		ManagementObserved: true, ManagementDescription: tool.Description,
		ManagementVersion: tool.Version, ManagementModifiedUserAgent: tool.ModifiedUserAgent,
		ToolID: tool.ID, ServerID: config.ServerID,
	}
	server, associated, associationErr := p.readAssociationStatus(ctx, client, config.ServerID, config.ToolName, tool)
	if associationErr != nil {
		return observation, associationErr
	}
	if server.TeamID != contract.Management.ServerTeamID || tool.TeamID != contract.Management.ToolTeamID {
		return observation, errors.New("receipt provider team identity does not match the current ContextForge rows")
	}
	claims, err := acceptedContextForgeClaims(token)
	if err != nil {
		return observation, err
	}
	principal, err := claims.resolvePrincipal(ctx, client)
	if err != nil {
		return observation, err
	}
	if err := claims.authorizePermissions(ctx, client, server, tool, principal); err != nil {
		return observation, err
	}
	if err := principal.authorizeOwnership(server, tool); err != nil {
		return observation, err
	}
	observation.Associated = associated
	if mcpObservation, observeErr := p.observeMCP(ctx, config); observeErr == nil {
		observation.MCPObserved = true
		observation.MCPDescription = mcpObservation.Description
	}
	return observation, nil
}

func (p *Poisoner) preflight(ctx context.Context, config contextForgeConfig) (preflightState, error) {
	token, err := resolveContextForgeToken(config.MCPURL, config.ManagementBase)
	if err != nil {
		return preflightState{}, fmt.Errorf("mcp poison: %w", err)
	}
	client, err := newContextForgeClient(config.ManagementBase, token, config.Insecure, p.clientTimeout())
	if err != nil {
		return preflightState{}, fmt.Errorf("mcp poison: build ContextForge client: %w", err)
	}
	mcpObservation, err := p.observeMCP(ctx, config)
	if err != nil {
		return preflightState{}, fmt.Errorf("mcp poison: observe MCP tool through initialized SDK session: %w", err)
	}
	server, tool, err := readBoundManagementTool(ctx, client, config.ServerID, config.ToolName)
	if err != nil {
		return preflightState{}, fmt.Errorf("mcp poison: ContextForge identity preflight: %w", err)
	}
	if tool.Description != mcpObservation.Description {
		return preflightState{}, errors.New("mcp poison: ContextForge association description does not match the SDK-observed MCP description")
	}
	claims, err := acceptedContextForgeClaims(token)
	if err != nil {
		return preflightState{}, fmt.Errorf("mcp poison: accepted token claims are invalid: %w", err)
	}
	principal, err := claims.resolvePrincipal(ctx, client)
	if err != nil {
		return preflightState{}, fmt.Errorf("mcp poison: authenticated identity preflight: %w", err)
	}
	if err := claims.authorizePermissions(ctx, client, server, tool, principal); err != nil {
		return preflightState{}, fmt.Errorf("mcp poison: permission preflight: %w", err)
	}
	if err := principal.authorizeOwnership(server, tool); err != nil {
		return preflightState{}, fmt.Errorf("mcp poison: authorization preflight: %w", err)
	}
	return preflightState{
		config: config, client: client, claims: claims, actor: principal,
		server: server, tool: tool, mcp: mcpObservation,
	}, nil
}

func readBoundManagementTool(ctx context.Context, client *contextForgeClient, serverID, toolName string) (contextForgeServer, contextForgeTool, error) {
	server, err := client.getServer(ctx, serverID)
	if err != nil {
		return contextForgeServer{}, contextForgeTool{}, fmt.Errorf("read server: %w", err)
	}
	if server.ID != serverID {
		return contextForgeServer{}, contextForgeTool{}, fmt.Errorf("server identity mismatch: got %q, expected %q", server.ID, serverID)
	}
	tools, err := client.listServerTools(ctx, serverID)
	if err != nil {
		return contextForgeServer{}, contextForgeTool{}, fmt.Errorf("read server tool association: %w", err)
	}
	var associated *contextForgeTool
	for i := range tools {
		if tools[i].Name != toolName {
			continue
		}
		if associated != nil {
			return contextForgeServer{}, contextForgeTool{}, fmt.Errorf("server association contains ambiguous MCP tool name %q", toolName)
		}
		associated = &tools[i]
	}
	if associated == nil {
		return contextForgeServer{}, contextForgeTool{}, fmt.Errorf("server association does not contain MCP tool name %q", toolName)
	}
	if !containsExactlyOnce(server.AssociatedToolIDs, associated.ID) {
		return contextForgeServer{}, contextForgeTool{}, fmt.Errorf("server association metadata does not contain exact tool UUID %q", associated.ID)
	}
	record, err := client.getTool(ctx, associated.ID)
	if err != nil {
		return contextForgeServer{}, contextForgeTool{}, fmt.Errorf("read exact tool record: %w", err)
	}
	if record.ID != associated.ID || record.Name != associated.Name || record.Description != associated.Description {
		return contextForgeServer{}, contextForgeTool{}, errors.New("server association and exact tool record identity do not match")
	}
	return server, record, nil
}

func containsExactlyOnce(values []string, expected string) bool {
	count := 0
	for _, value := range values {
		if value == expected {
			count++
		}
	}
	return count == 1
}

func (p *Poisoner) observeMCP(ctx context.Context, config contextForgeConfig) (mcp.ToolObservation, error) {
	authorization, err := resolveMCPAuthorization(config.MCPURL)
	if err != nil {
		return mcp.ToolObservation{}, err
	}
	headers := map[string]string{}
	if authorization != "" {
		headers["Authorization"] = authorization
	}
	return (mcp.ToolObserver{
		InitTimeout: DefaultProbeTimeout, MaxItems: 10000,
		MaxResponseBytes: contextForgeMaxResponseBytes,
		Insecure:         config.Insecure, RejectRedirects: true,
	}).Observe(ctx, mcp.ServerSpec{
		Name: config.ToolName, Transport: "http", URL: config.MCPURL, Headers: headers,
	}, config.ToolName)
}

func (p *Poisoner) pollManagement(ctx context.Context, client *contextForgeClient, toolID string, accept func(contextForgeTool) bool) (contextForgeTool, error) {
	attempts := p.attempts()
	var lastErr error
	var last contextForgeTool
	for attempt := 0; attempt < attempts; attempt++ {
		current, err := client.getTool(ctx, toolID)
		if err == nil {
			last = current
			if accept(current) {
				return current, nil
			}
		} else {
			lastErr = err
		}
		if err := p.waitPoll(ctx, attempt, attempts); err != nil {
			return last, err
		}
	}
	if lastErr != nil {
		return last, lastErr
	}
	return last, errors.New("bounded ContextForge propagation polling exhausted")
}

func (p *Poisoner) pollMCP(ctx context.Context, config contextForgeConfig, expected string) (mcp.ToolObservation, error) {
	attempts := p.attempts()
	var lastErr error
	var last mcp.ToolObservation
	for attempt := 0; attempt < attempts; attempt++ {
		observed, err := p.observeMCP(ctx, config)
		if err == nil {
			last = observed
			if observed.Description == expected {
				return observed, nil
			}
		} else {
			lastErr = err
		}
		if err := p.waitPoll(ctx, attempt, attempts); err != nil {
			return last, err
		}
	}
	if lastErr != nil {
		return last, lastErr
	}
	return last, errors.New("bounded MCP propagation polling exhausted")
}

func (p *Poisoner) waitPoll(ctx context.Context, attempt, attempts int) error {
	if attempt+1 >= attempts || p.pollInterval <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(p.pollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *Poisoner) attempts() int {
	if p.pollAttempts < 1 {
		return 1
	}
	return p.pollAttempts
}

func (p *Poisoner) clientTimeout() time.Duration {
	if p.campaign {
		return 0
	}
	return contextForgeTimeout
}

func (p *Poisoner) cleanupOwnedForward(ctx context.Context, state preflightState, receipt *action.PoisonReceipt, managementOnly bool) error {
	contract := receipt.ContextForge
	response, responseErr := state.client.putDescription(
		ctx, state.tool.ID, state.tool.Description, contract.Management.RestoreUserAgent,
	)
	if responseErr == nil {
		responseErr = validateRestoreResponse(response, contract)
	}
	if err := p.verifyRestored(ctx, state.client, state.config, contract, managementOnly); err != nil {
		if responseErr != nil {
			return fmt.Errorf("cleanup response invalid (%v) and verification failed: %w", responseErr, err)
		}
		return err
	}
	return nil
}

func (p *Poisoner) verifyRestored(ctx context.Context, client *contextForgeClient, config contextForgeConfig, contract *action.ContextForgeToolDescriptionReceipt, managementOnly bool) error {
	management, err := p.pollManagement(ctx, client, contract.Management.ToolID, func(tool contextForgeTool) bool {
		return tool.Description == contract.Management.OriginalDescription &&
			tool.Version == contract.Management.OriginalVersion+2 &&
			tool.ModifiedUserAgent == contract.Management.RestoreUserAgent
	})
	if err != nil {
		return fmt.Errorf("verify restored ContextForge state: %w", err)
	}
	if management.ID != contract.Management.ToolID || management.Name != contract.Management.ToolName {
		return errors.New("verify restored ContextForge identity mismatch")
	}
	if managementOnly {
		return nil
	}
	_, associated, associationErr := p.readAssociationStatus(ctx, client, config.ServerID, config.ToolName, management)
	if associationErr != nil || !associated {
		return fmt.Errorf("verify restored ContextForge association: associated=%t: %v", associated, associationErr)
	}
	if _, err := p.pollMCP(ctx, config, contract.MCP.OriginalDescription); err != nil {
		return fmt.Errorf("verify restored MCP state: %w", err)
	}
	return nil
}

func validateWriteResponse(response, original contextForgeTool, description, userAgent string) error {
	if !forwardWriteOwned(response, original, userAgent) || response.Description != description {
		return contextForgeContractError{errors.New("ContextForge PUT response did not contain the exact updated identity, description, version, and operation attribution")}
	}
	return nil
}

func validateRestoreResponse(response contextForgeTool, contract *action.ContextForgeToolDescriptionReceipt) error {
	if response.ID != contract.Management.ToolID || response.Name != contract.Management.ToolName ||
		response.Description != contract.Management.OriginalDescription ||
		response.Version != contract.Management.OriginalVersion+2 ||
		response.ModifiedUserAgent != contract.Management.RestoreUserAgent {
		return contextForgeContractError{errors.New("ContextForge restore response did not contain the exact original description, expected version, and operation attribution")}
	}
	return nil
}

func forwardWriteOwned(current, original contextForgeTool, userAgent string) bool {
	return current.ID == original.ID && current.Name == original.Name &&
		current.Version == original.Version+1 && current.ModifiedUserAgent == userAgent
}

func composeContent(original, injection, mode string) string {
	switch mode {
	case "append":
		return original + injection
	case "prepend":
		return injection + original
	default:
		return injection
	}
}

func (p *Poisoner) rejectRepeatedEngagementTarget(engagementID string, state preflightState) error {
	receipts, err := p.stateful.ReadReceipts(engagementID)
	if err != nil {
		return fmt.Errorf("mcp poison: read existing engagement receipts before mutation: %w", err)
	}
	for _, candidate := range receipts {
		receipt, ok := normalizeReceipt(candidate)
		if !ok || receipt == nil || receipt.DryRun || receipt.ContextForge == nil {
			continue
		}
		contract := receipt.ContextForge
		if contract.Management.BaseURL == state.config.ManagementBase &&
			contract.Management.ToolID == state.tool.ID &&
			contract.Management.OriginalDescription != state.tool.Description {
			return errors.New("mcp poison: this engagement already has a live ContextForge receipt for the exact tool; revert it or use a new engagement ID before poisoning the same row again")
		}
	}
	return nil
}

func hasAgentHoundForwardAttribution(userAgent string) bool {
	return strings.HasPrefix(userAgent, "AgentHound/contextforge-tool-description receipt/") &&
		strings.Contains(userAgent, " operation/forward/")
}

func newContextForgeReceipt(target action.Target, payload action.PoisonPayload, mode string, state preflightState, updated string) (*action.PoisonReceipt, error) {
	receiptID, err := action.NewReceiptID()
	if err != nil {
		return nil, fmt.Errorf("mcp poison: create receipt id: %w", err)
	}
	forwardOperationID, err := action.NewReceiptID()
	if err != nil {
		return nil, fmt.Errorf("mcp poison: create forward operation id: %w", err)
	}
	restoreOperationID, err := action.NewReceiptID()
	if err != nil {
		return nil, fmt.Errorf("mcp poison: create restore operation id: %w", err)
	}
	forwardUA := operationUserAgent(receiptID, forwardOperationID, "forward")
	restoreUA := operationUserAgent(receiptID, restoreOperationID, "restore")
	var originalUA *string
	if state.tool.ModifiedUserAgent != "" {
		value := state.tool.ModifiedUserAgent
		originalUA = &value
	}
	contract := &action.ContextForgeToolDescriptionReceipt{
		ReceiptType: action.ContextForgeReceiptType, ReceiptVersion: action.ContextForgeReceiptVersion,
		Profile: action.ContextForgeProfile, ContractID: action.ContextForgeContractID,
		MCP: action.ContextForgeMCPState{
			URL: state.config.MCPURL, ToolName: state.config.ToolName,
			OriginalDescription: state.tool.Description, UpdatedDescription: updated,
		},
		Management: action.ContextForgeManagementState{
			BaseURL: state.config.ManagementBase, ServerID: state.config.ServerID,
			ToolID: state.tool.ID, ToolName: state.tool.Name,
			ServerTeamID: state.server.TeamID, ToolTeamID: state.tool.TeamID,
			IdentityReadPath:          identityReadPath(),
			ServerPermissionsReadPath: permissionsReadPath(state.server.TeamID),
			ToolPermissionsReadPath:   permissionsReadPath(state.tool.TeamID),
			ServerReadPath:            serverReadPath(state.config.ServerID),
			AssociationReadPath:       associationReadPath(state.config.ServerID),
			RecordReadPath:            recordReadPath(state.tool.ID), WritePath: writePath(state.tool.ID),
			Method: http.MethodPut, ExpectedStatus: http.StatusOK,
			OriginalDescription: state.tool.Description, UpdatedDescription: updated,
			OriginalVersion: state.tool.Version, OriginalModifiedUserAgent: originalUA,
			ForwardOperationID: forwardOperationID, RestoreOperationID: restoreOperationID,
			ForwardUserAgent: forwardUA, RestoreUserAgent: restoreUA,
		},
	}
	return &action.PoisonReceipt{
		ReceiptID: receiptID, ModuleID: "mcp.poison", EngagementID: payload.EngagementID,
		CampaignRunID: payload.CampaignRunID, StepSequence: payload.StepSequence,
		Target: action.Target{Kind: target.Kind, Address: state.config.MCPURL}, TargetID: state.config.ToolName,
		OriginalContent: state.tool.Description, InjectedContent: updated, Mode: mode,
		AppliedAt: time.Now().UTC(), DryRun: payload.DryRun, ContextForge: contract,
	}, nil
}

func operationUserAgent(receiptID, operationID, operation string) string {
	return "AgentHound/contextforge-tool-description receipt/" + receiptID + " operation/" + operation + "/" + operationID
}

func validateContextForgeReceipt(receipt *action.PoisonReceipt) error {
	if receipt == nil || receipt.ContextForge == nil {
		return errors.New("missing typed ContextForge receipt")
	}
	contract := receipt.ContextForge
	if contract.ReceiptType != action.ContextForgeReceiptType {
		return fmt.Errorf("unknown receipt_type %q", contract.ReceiptType)
	}
	if contract.ReceiptVersion != action.ContextForgeReceiptVersion {
		return fmt.Errorf("unknown receipt_version %d", contract.ReceiptVersion)
	}
	if contract.Profile != action.ContextForgeProfile {
		return fmt.Errorf("unknown management_profile %q", contract.Profile)
	}
	if contract.ContractID != action.ContextForgeContractID {
		return fmt.Errorf("unknown contract_id %q", contract.ContractID)
	}
	if receipt.ModuleID != "mcp.poison" || strings.TrimSpace(receipt.ReceiptID) == "" {
		return errors.New("receipt module or receipt id is invalid")
	}
	if receipt.Target.Address != contract.MCP.URL || len(receipt.Target.Meta) != 0 {
		return errors.New("receipt target must contain only the canonical MCP URL")
	}
	decodedReceiptID, err := base64.RawURLEncoding.DecodeString(receipt.ReceiptID)
	if err != nil || len(decodedReceiptID) != 18 {
		return errors.New("receipt id is invalid")
	}
	mcpURL, serverID, _, err := parseContextForgeMCPURL(contract.MCP.URL)
	if err != nil || mcpURL != contract.MCP.URL || serverID != contract.Management.ServerID {
		return errors.New("receipt MCP URL and server identity are inconsistent")
	}
	base, err := validateManagementBase(contract.Management.BaseURL)
	if err != nil || base != contract.Management.BaseURL {
		return errors.New("receipt management base URL is invalid")
	}
	if _, err := canonicalUUID(contract.Management.ToolID, "receipt tool id"); err != nil {
		return err
	}
	if contract.MCP.ToolName == "" || contract.MCP.ToolName != contract.Management.ToolName ||
		contract.MCP.ToolName != receipt.TargetID {
		return errors.New("receipt MCP and management tool names are inconsistent")
	}
	if contract.MCP.OriginalDescription != contract.Management.OriginalDescription ||
		contract.MCP.UpdatedDescription != contract.Management.UpdatedDescription ||
		receipt.OriginalContent != contract.MCP.OriginalDescription ||
		receipt.InjectedContent != contract.MCP.UpdatedDescription {
		return errors.New("receipt descriptions are inconsistent")
	}
	if contract.Management.OriginalVersion < 1 ||
		contract.Management.IdentityReadPath != identityReadPath() ||
		contract.Management.ServerPermissionsReadPath != permissionsReadPath(contract.Management.ServerTeamID) ||
		contract.Management.ToolPermissionsReadPath != permissionsReadPath(contract.Management.ToolTeamID) ||
		contract.Management.ServerReadPath != serverReadPath(serverID) ||
		contract.Management.AssociationReadPath != associationReadPath(serverID) ||
		contract.Management.RecordReadPath != recordReadPath(contract.Management.ToolID) ||
		contract.Management.WritePath != writePath(contract.Management.ToolID) ||
		contract.Management.Method != http.MethodPut || contract.Management.ExpectedStatus != http.StatusOK {
		return errors.New("receipt management contract does not match the fixed ContextForge adapter")
	}
	for label, teamID := range map[string]string{
		"receipt server team id": contract.Management.ServerTeamID,
		"receipt tool team id":   contract.Management.ToolTeamID,
	} {
		if teamID != "" {
			if _, err := canonicalUUID(teamID, label); err != nil {
				return err
			}
		}
	}
	if !validOpaqueOperationID(contract.Management.ForwardOperationID) ||
		!validOpaqueOperationID(contract.Management.RestoreOperationID) ||
		contract.Management.ForwardOperationID == contract.Management.RestoreOperationID {
		return errors.New("receipt operation ids are invalid")
	}
	if contract.Management.ForwardUserAgent != operationUserAgent(receipt.ReceiptID, contract.Management.ForwardOperationID, "forward") ||
		contract.Management.RestoreUserAgent != operationUserAgent(receipt.ReceiptID, contract.Management.RestoreOperationID, "restore") {
		return errors.New("receipt operation attribution is invalid")
	}
	return nil
}

func validOpaqueOperationID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 18
}

func normalizeReceipt(receipt action.Receipt) (*action.PoisonReceipt, bool) {
	switch value := receipt.(type) {
	case *action.PoisonReceipt:
		return value, true
	case action.PoisonReceipt:
		return &value, true
	default:
		return nil, false
	}
}

func observationFrom(server contextForgeServer, tool contextForgeTool, observed mcp.ToolObservation, associated bool) Observation {
	return Observation{
		Associated: associated, MCPObserved: true, ManagementObserved: true,
		MCPDescription: observed.Description, ManagementDescription: tool.Description,
		ManagementVersion: tool.Version, ManagementModifiedUserAgent: tool.ModifiedUserAgent,
		ToolID: tool.ID, ServerID: server.ID,
	}
}

func (p *Poisoner) readManagementState(ctx context.Context, client *contextForgeClient, serverID, toolName, toolID string) (contextForgeServer, bool, contextForgeTool, error) {
	tool, err := client.getTool(ctx, toolID)
	if err != nil {
		return contextForgeServer{}, false, contextForgeTool{}, err
	}
	if tool.ID != toolID {
		return contextForgeServer{}, false, contextForgeTool{}, errors.New("exact ContextForge tool read returned a different tool UUID")
	}
	if tool.Name != toolName {
		return contextForgeServer{}, false, contextForgeTool{}, fmt.Errorf("exact ContextForge tool name changed: %w", action.ErrRevertConflict)
	}
	server, associated, err := p.readAssociationStatus(ctx, client, serverID, toolName, tool)
	return server, associated, tool, err
}

func (p *Poisoner) readAssociationStatus(ctx context.Context, client *contextForgeClient, serverID, toolName string, exact contextForgeTool) (contextForgeServer, bool, error) {
	server, err := client.getServer(ctx, serverID)
	if err != nil {
		return contextForgeServer{}, false, err
	}
	if server.ID != serverID {
		return contextForgeServer{}, false, errors.New("server identity mismatch")
	}
	tools, err := client.listServerTools(ctx, serverID)
	if err != nil {
		return contextForgeServer{}, false, err
	}
	matchCount := 0
	exactMatch := false
	for _, tool := range tools {
		if tool.Name != toolName {
			continue
		}
		matchCount++
		if tool.ID == exact.ID && tool.Description == exact.Description {
			exactMatch = true
		}
	}
	associated := matchCount == 1 && exactMatch && containsExactlyOnce(server.AssociatedToolIDs, exact.ID)
	return server, associated, nil
}

var _ action.Poisoner = (*Poisoner)(nil)
