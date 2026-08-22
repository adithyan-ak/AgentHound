package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/adithyan-ak/agenthound/modules/mcppoison"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/contact"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

const contextForgeActionID = "mcp.description.roundtrip"

var errCleanupUnresolved = errors.New("mutation cleanup remains unresolved")

type contextForgeRoundTripAction struct {
	insecure bool
	policy   *contact.Policy
}

func (contextForgeRoundTripAction) ID() string { return contextForgeActionID }

func (a contextForgeRoundTripAction) Candidates(view View) []Candidate {
	if view.Stealth {
		return nil
	}
	var candidates []Candidate
	seen := make(map[string]bool)
	for _, server := range view.ByKind["MCPServer"] {
		endpoint := stringProperty(server.Properties, "endpoint")
		if endpoint == "" || stringProperty(server.Properties, "transport") != "http" {
			continue
		}
		if err := mcppoison.ValidateContextForgeEndpoints(endpoint, ""); err != nil {
			continue
		}
		credentialIDs := directCredentialIDs(view, server.ID)
		if len(credentialIDs) == 0 {
			continue
		}
		toolIDs := targetsForEdge(view.Outgoing[server.ID], "PROVIDES_TOOL")
		for _, credentialID := range orderedCredentialIDs(view, credentialIDs) {
			if !credentialIDs[credentialID] {
				continue
			}
			credential, present := view.Nodes[credentialID]
			if !present || !bearerCredential(credential) {
				continue
			}
			material := normalizeBearer(view.Credentials[credentialID])
			if material == "" {
				continue
			}
			for _, toolID := range toolIDs {
				tool, present := view.Nodes[toolID]
				if !present {
					continue
				}
				toolName := stringProperty(tool.Properties, "name")
				if toolName == "" {
					continue
				}
				candidate := Candidate{
					Priority: 5, ModuleID: a.ID(), CredentialID: credentialID,
					ResourceID: toolID,
					Target: action.Target{Kind: "url", Address: endpoint, Meta: map[string]string{
						"url": endpoint, "node_id": server.ID,
					}},
					PathNodeIDs: []string{server.ID, credentialID, toolID},
					Inputs: map[string]string{
						"credential": material, "tool_name": toolName, "server_id": server.ID,
					},
				}
				candidate.Key = candidateKey(
					a.ID(), endpoint, stringProperty(credential.Properties, "value_hash"), toolID, view.Deep,
				)
				if seen[candidate.Key] {
					continue
				}
				seen[candidate.Key] = true
				candidates = append(candidates, candidate)
			}
		}
	}
	return candidates
}

func (a contextForgeRoundTripAction) Execute(ctx context.Context, candidate Candidate, journal Journal) (Result, error) {
	actionID := candidate.Inputs["action_id"]
	if actionID == "" {
		return Result{}, errors.New("ContextForge round-trip action id is required")
	}
	state := &artifactReceiptStore{
		actionID: actionID, credentialIDs: []string{candidate.CredentialID}, journal: journal,
		insecure: a.insecure,
	}
	poisoner := mcppoison.New()
	poisoner.SetReceiptJournal(state)
	poisoner.SetAfterWrite(func(receipt *action.PoisonReceipt) error {
		return journal.MarkApplied(receipt.ReceiptID)
	})

	marker := "agenthound:" + candidate.Inputs["scan_id"] + ":" + uuid.NewString()
	receipt, mutationErr := poisoner.Poison(ctx, candidate.Target, action.PoisonPayload{
		InjectionContent: marker,
		TargetID:         candidate.Inputs["tool_name"],
		Mode:             "append",
		RunID:            actionID,
		Extras: map[string]any{
			"adapter": action.ContextForgeProfile, "insecure": a.insecure,
			"credential": candidate.Inputs["credential"],
		},
	})
	if receipt == nil {
		return Result{Outcome: "mutation_not_applied"}, mutationErr
	}

	// Cleanup is deliberately detached from the forward context. Once the
	// write may have happened, a deadline or signal cannot cancel restoration.
	cleanupBase := contact.WithPolicy(context.Background(), a.policy)
	cleanupBase = mcppoison.WithToken(cleanupBase, candidate.Inputs["credential"])
	if a.insecure {
		cleanupBase = context.WithValue(cleanupBase, action.RevertInsecureKey{}, true)
	}
	cleanupCtx, cancel := context.WithTimeout(cleanupBase, perReceiptRevertTimeout)
	cleanupErr := poisoner.Revert(cleanupCtx, receipt)
	cancel()
	if cleanupErr != nil {
		outcome := "cleanup_unresolved"
		if mutationErr == nil {
			outcome = "mutation_observed_cleanup_unresolved"
		}
		return Result{Outcome: outcome}, fmt.Errorf("%w: %v", errCleanupUnresolved, cleanupErr)
	}
	if err := journal.MarkRestored(receipt.ReceiptID); err != nil {
		return Result{Outcome: "restored_checkpoint_failed"}, err
	}
	if mutationErr != nil {
		return Result{Outcome: "mutation_failed_restored"}, mutationErr
	}
	return Result{Outcome: "mutation_observed_restored"}, nil
}

// artifactReceiptStore adapts the existing, thoroughly tested ContextForge
// mutator to the scan's single-file Journal. It never writes a sidecar.
type artifactReceiptStore struct {
	mu            sync.Mutex
	actionID      string
	credentialIDs []string
	journal       Journal
	receipts      []action.Receipt
	insecure      bool
}

func (s *artifactReceiptStore) WriteReceipt(_ string, raw action.Receipt) (string, error) {
	receipt, ok := raw.(*action.PoisonReceipt)
	if !ok || receipt == nil || receipt.ContextForge == nil {
		return "", fmt.Errorf("unsupported ContextForge recovery receipt %T", raw)
	}
	data := contextForgeRecoveryFromReceipt(receipt, s.insecure)
	record := ingest.RecoveryRecord{
		ID: receipt.ReceiptID, ActionID: s.actionID, Action: contextForgeActionID,
		CredentialIDs: append([]string(nil), s.credentialIDs...),
		Data:          map[string]any{"contextforge": recoveryData(data)},
	}
	if err := s.journal.Prepare(s.actionID, record); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.receipts = append(s.receipts, contextForgeReceiptFromRecovery(data))
	s.mu.Unlock()
	return "scan artifact", nil
}

func (s *artifactReceiptStore) ReadReceipts(string) ([]action.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]action.Receipt(nil), s.receipts...), nil
}

type contextForgeRecoveryData struct {
	ReceiptID       string                                    `json:"receipt_id"`
	TargetKind      string                                    `json:"target_kind"`
	TargetID        string                                    `json:"target_id"`
	OriginalContent string                                    `json:"original_content"`
	InjectedContent string                                    `json:"injected_content"`
	Mode            string                                    `json:"mode"`
	AppliedAt       time.Time                                 `json:"applied_at"`
	Insecure        bool                                      `json:"insecure"`
	ContextForge    action.ContextForgeToolDescriptionReceipt `json:"contextforge"`
}

func contextForgeRecoveryFromReceipt(receipt *action.PoisonReceipt, insecure bool) contextForgeRecoveryData {
	return contextForgeRecoveryData{
		ReceiptID: receipt.ReceiptID, TargetKind: receipt.Target.Kind, TargetID: receipt.TargetID,
		OriginalContent: receipt.OriginalContent, InjectedContent: receipt.InjectedContent,
		Mode: receipt.Mode, AppliedAt: receipt.AppliedAt, Insecure: insecure, ContextForge: *receipt.ContextForge,
	}
}

func contextForgeReceiptFromRecovery(data contextForgeRecoveryData) *action.PoisonReceipt {
	contract := data.ContextForge
	return &action.PoisonReceipt{
		ReceiptID: data.ReceiptID, ModuleID: "mcp.poison",
		Target: action.Target{Kind: data.TargetKind, Address: contract.MCP.URL}, TargetID: data.TargetID,
		OriginalContent: data.OriginalContent, InjectedContent: data.InjectedContent,
		Mode: data.Mode, AppliedAt: data.AppliedAt, ContextForge: &contract,
	}
}

func decodeContextForgeRecovery(record ingest.RecoveryRecord) (contextForgeRecoveryData, error) {
	value, present := record.Data["contextforge"]
	if !present {
		return contextForgeRecoveryData{}, errors.New("recovery data has no contextforge state")
	}
	document, err := json.Marshal(value)
	if err != nil {
		return contextForgeRecoveryData{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	decoder.DisallowUnknownFields()
	var data contextForgeRecoveryData
	if err := decoder.Decode(&data); err != nil {
		return contextForgeRecoveryData{}, err
	}
	if data.ReceiptID == "" || data.ContextForge.MCP.URL == "" {
		return contextForgeRecoveryData{}, errors.New("ContextForge recovery data is incomplete")
	}
	return data, nil
}

func normalizeBearer(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "bearer ") {
		value = strings.TrimSpace(value[len("bearer "):])
	}
	return value
}
