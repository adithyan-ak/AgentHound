package action

import (
	"context"
	"time"
)

// Poisoner injects content into an upstream artifact a Target consumes
// (config file, instruction file, tool description, etc.). Composes
// Reverter so every poison has an explicit recovery implementation. Callers
// must verify the runtime result because providers, conflicts, or unavailable
// targets can still prevent complete restoration.
//
// Implementations also implement sdk/module.Module.
//
// Every Poisoner emits a PoisonReceipt that carries the original content and
// provider-specific rollback state plus
// engagement metadata. Receipts are persisted by the StatefulModule
// sidecar (sdk/module/stateful.go) keyed on engagement-id so
// `agenthound revert <engagement-id>` walks all module state dirs and
// dispatches per-module Revert.
type Poisoner interface {
	Reverter
	// Poison returns a non-nil receipt with ErrRevertIndeterminate when a
	// committed write may remain after an error. An error after verified
	// automatic restoration must not use that sentinel.
	Poison(ctx context.Context, t Target, payload PoisonPayload) (*PoisonReceipt, error)
}

// PoisonPayload describes one Poison invocation.
//
// TargetID is the per-module logical address of what is being poisoned —
// for the MCP tool Poisoner this is the MCPTool.objectid. For an
// instruction-file Poisoner it is the absolute file path.
//
// Mode controls how InjectionContent combines with existing content:
//
//	"append"   — add InjectionContent at the end of the original
//	"prepend"  — add InjectionContent at the start of the original
//	"replace"  — overwrite the original entirely
//
// EngagementID is recorded on the receipt and on every emitted edge's
// evidence map. DryRun=true runs the same read-only preflight and eligibility
// checks without any mutating HTTP/file write — receipt is written with
// DryRun=true so `agenthound revert` knows to skip it.
type PoisonPayload struct {
	InjectionContent string
	TargetID         string
	Mode             string
	EngagementID     string
	CampaignRunID    string
	StepSequence     uint64
	DryRun           bool

	// Extras carries per-Poisoner flag values populated by the CLI dispatch
	// from the Poisoner's FlagsModule.RegisterFlags surface. Mirrors
	// LootOptions.Extras — same pattern, different action.
	Extras map[string]any
}

// PoisonReceipt is what every Poisoner returns and what Revert consumes.
// OriginalContent is mandatory — without it, revert is impossible. The
// CLI persists the receipt via StatefulModule before declaring the
// poison "applied", so a crash between the HTTP write and the receipt
// write would leave a tampered target without a revert path.
type PoisonReceipt struct {
	ReceiptID       string
	ModuleID        string
	EngagementID    string
	CampaignRunID   string
	StepSequence    uint64
	Target          Target
	TargetID        string
	OriginalContent string
	InjectedContent string
	Mode            string
	AppliedAt       time.Time
	DryRun          bool

	// Extra carries per-Poisoner state the Reverter needs to undo this
	// poison cleanly (e.g. content-type, transport metadata). Optional —
	// receipts that don't need it leave it nil.
	Extra map[string]any

	// ContextForge is the provider-specific rollback contract for an MCP tool
	// description managed by ContextForge. MCP has no metadata-update method;
	// this state deliberately records the distinct protocol and management
	// surfaces. Revert rejects MCP receipts without this typed state.
	ContextForge *ContextForgeToolDescriptionReceipt `json:"contextforge,omitempty"`
}

const (
	ContextForgeReceiptType    = "mcp_tool_description_contextforge"
	ContextForgeReceiptVersion = 1
	ContextForgeContractID     = "contextforge-v1-tool-description-put"
	ContextForgeProfile        = "contextforge"
)

// ContextForgeToolDescriptionReceipt is immutable, write-once recovery state.
// It contains no credentials. Operation User-Agents are generated before the
// receipt is persisted and let the reverter distinguish AgentHound's write
// from a later writer when ContextForge exposes no conditional update.
type ContextForgeToolDescriptionReceipt struct {
	ReceiptType    string                      `json:"receipt_type"`
	ReceiptVersion int                         `json:"receipt_version"`
	Profile        string                      `json:"management_profile"`
	ContractID     string                      `json:"contract_id"`
	MCP            ContextForgeMCPState        `json:"mcp"`
	Management     ContextForgeManagementState `json:"management"`
}

type ContextForgeMCPState struct {
	URL                 string `json:"url"`
	ToolName            string `json:"tool_name"`
	OriginalDescription string `json:"original_description"`
	UpdatedDescription  string `json:"updated_description"`
}

type ContextForgeManagementState struct {
	BaseURL                   string  `json:"base_url"`
	ServerID                  string  `json:"server_id"`
	ToolID                    string  `json:"tool_id"`
	ToolName                  string  `json:"tool_name"`
	ServerTeamID              string  `json:"server_team_id,omitempty"`
	ToolTeamID                string  `json:"tool_team_id,omitempty"`
	IdentityReadPath          string  `json:"identity_read_path"`
	ServerPermissionsReadPath string  `json:"server_permissions_read_path"`
	ToolPermissionsReadPath   string  `json:"tool_permissions_read_path"`
	ServerReadPath            string  `json:"server_read_path"`
	AssociationReadPath       string  `json:"association_read_path"`
	RecordReadPath            string  `json:"record_read_path"`
	WritePath                 string  `json:"write_path"`
	Method                    string  `json:"method"`
	ExpectedStatus            int     `json:"expected_status"`
	OriginalDescription       string  `json:"original_description"`
	UpdatedDescription        string  `json:"updated_description"`
	OriginalVersion           int64   `json:"original_version"`
	OriginalModifiedUserAgent *string `json:"original_modified_user_agent"`
	ForwardOperationID        string  `json:"forward_operation_id"`
	RestoreOperationID        string  `json:"restore_operation_id"`
	ForwardUserAgent          string  `json:"forward_user_agent"`
	RestoreUserAgent          string  `json:"restore_user_agent"`
}
