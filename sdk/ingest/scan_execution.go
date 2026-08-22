package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"
)

const (
	ScanExecutionExtraKey = "scan_execution"
	ScanExecutionVersion  = 1
)

type ScanMode string

const (
	ScanModeActive  ScanMode = "active"
	ScanModeStealth ScanMode = "stealth"
)

type ScanExecutionStatus string

const (
	ScanExecutionRunning     ScanExecutionStatus = "running"
	ScanExecutionCompleted   ScanExecutionStatus = "completed"
	ScanExecutionInterrupted ScanExecutionStatus = "interrupted"
	ScanExecutionFailed      ScanExecutionStatus = "failed"
)

type ActionStatus string

const (
	ActionRunning   ActionStatus = "running"
	ActionSucceeded ActionStatus = "succeeded"
	ActionFailed    ActionStatus = "failed"
	ActionBlocked   ActionStatus = "blocked"
	ActionSkipped   ActionStatus = "skipped"
)

type RecoveryStatus string

const (
	RecoveryPrepared      RecoveryStatus = "prepared"
	RecoveryApplied       RecoveryStatus = "applied"
	RecoveryRestored      RecoveryStatus = "restored"
	RecoveryConflict      RecoveryStatus = "conflict"
	RecoveryIndeterminate RecoveryStatus = "indeterminate"
	RecoveryFailed        RecoveryStatus = "failed"
)

// ScanExecution is the V1 autonomous-scan execution record carried in
// meta.extra.scan_execution. It remains part of the artifact so checkpoint
// recovery never has to reconcile a sidecar with the ingest envelope.
type ScanExecution struct {
	Version     int                 `json:"version"`
	Mode        ScanMode            `json:"mode"`
	Deep        bool                `json:"deep"`
	Exclusions  []string            `json:"exclusions"`
	Status      ScanExecutionStatus `json:"status"`
	StartedAt   string              `json:"started_at"`
	UpdatedAt   string              `json:"updated_at"`
	CompletedAt *string             `json:"completed_at"`
	Summary     ExecutionSummary    `json:"summary"`
	Actions     []ActionRecord      `json:"actions"`
	Recovery    []RecoveryRecord    `json:"recovery"`
}

type ExecutionSummary struct {
	ActionsAttempted int `json:"actions_attempted"`
	ActionsSucceeded int `json:"actions_succeeded"`
	ActionsFailed    int `json:"actions_failed"`
	ActionsSkipped   int `json:"actions_skipped"`
	CleanupFailures  int `json:"cleanup_failures"`
}

type ActionRecord struct {
	ID           string       `json:"id"`
	Action       string       `json:"action"`
	TargetID     string       `json:"target_id"`
	CredentialID string       `json:"credential_id,omitempty"`
	ResourceID   string       `json:"resource_id,omitempty"`
	PathNodeIDs  []string     `json:"path_node_ids"`
	Status       ActionStatus `json:"status"`
	Outcome      string       `json:"outcome"`
	Error        string       `json:"error"`
	RecoveryID   string       `json:"recovery_id,omitempty"`
	StartedAt    string       `json:"started_at"`
	CompletedAt  string       `json:"completed_at"`
}

type RecoveryRecord struct {
	ID            string         `json:"id"`
	ActionID      string         `json:"action_id"`
	Action        string         `json:"action"`
	Status        RecoveryStatus `json:"status"`
	PreparedAt    string         `json:"prepared_at"`
	UpdatedAt     string         `json:"updated_at"`
	CredentialIDs []string       `json:"credential_ids"`
	Data          map[string]any `json:"data"`
	Error         string         `json:"error"`
}

func (e ScanExecution) MarshalJSON() ([]byte, error) {
	type wire ScanExecution
	e.normalize()
	return json.Marshal(wire(e))
}

func (a ActionRecord) MarshalJSON() ([]byte, error) {
	type wire ActionRecord
	if a.PathNodeIDs == nil {
		a.PathNodeIDs = []string{}
	}
	return json.Marshal(wire(a))
}

func (r RecoveryRecord) MarshalJSON() ([]byte, error) {
	type wire RecoveryRecord
	if r.CredentialIDs == nil {
		r.CredentialIDs = []string{}
	}
	return json.Marshal(wire(r))
}

// NewScanExecution constructs an initialized running execution record.
func NewScanExecution(mode ScanMode, deep bool, now time.Time) *ScanExecution {
	stamp := formatExecutionTime(now)
	return &ScanExecution{
		Version:    ScanExecutionVersion,
		Mode:       mode,
		Deep:       deep,
		Exclusions: []string{},
		Status:     ScanExecutionRunning,
		StartedAt:  stamp,
		UpdatedAt:  stamp,
		Actions:    []ActionRecord{},
		Recovery:   []RecoveryRecord{},
	}
}

// RecomputeSummary derives all counters from the action and recovery records.
// Blocked and skipped actions were not attempted. Every recovery record that
// has not reached restored is unresolved and therefore a cleanup failure.
func (e *ScanExecution) RecomputeSummary() {
	if e == nil {
		return
	}
	var summary ExecutionSummary
	for _, record := range e.Actions {
		switch record.Status {
		case ActionRunning:
			summary.ActionsAttempted++
		case ActionSucceeded:
			summary.ActionsAttempted++
			summary.ActionsSucceeded++
		case ActionFailed:
			summary.ActionsAttempted++
			summary.ActionsFailed++
		case ActionBlocked, ActionSkipped:
			summary.ActionsSkipped++
		}
	}
	for _, record := range e.Recovery {
		if record.Status != RecoveryRestored {
			summary.CleanupFailures++
		}
	}
	e.Summary = summary
}

// Validate checks the strict V1 execution contract, record IDs, references,
// timestamps, enum values, and the derived summary.
func (e *ScanExecution) Validate() error {
	if e == nil {
		return fmt.Errorf("scan execution is required")
	}
	if e.Version != ScanExecutionVersion {
		return fmt.Errorf("version = %d, want %d", e.Version, ScanExecutionVersion)
	}
	if e.Mode != ScanModeActive && e.Mode != ScanModeStealth {
		return fmt.Errorf("unsupported mode %q", e.Mode)
	}
	switch e.Status {
	case ScanExecutionRunning, ScanExecutionCompleted, ScanExecutionInterrupted, ScanExecutionFailed:
	default:
		return fmt.Errorf("unsupported status %q", e.Status)
	}
	if err := validateExecutionTime("started_at", e.StartedAt, true); err != nil {
		return err
	}
	if err := validateExecutionTime("updated_at", e.UpdatedAt, true); err != nil {
		return err
	}
	if e.CompletedAt != nil {
		if err := validateExecutionTime("completed_at", *e.CompletedAt, true); err != nil {
			return err
		}
	}
	if e.Actions == nil {
		return fmt.Errorf("actions must be an array")
	}
	if e.Recovery == nil {
		return fmt.Errorf("recovery must be an array")
	}
	if e.Exclusions == nil {
		return fmt.Errorf("exclusions must be an array")
	}
	if err := validateStringIDs("exclusions", e.Exclusions); err != nil {
		return err
	}

	actions := make(map[string]ActionRecord, len(e.Actions))
	for index, record := range e.Actions {
		prefix := fmt.Sprintf("actions[%d]", index)
		if record.PathNodeIDs == nil {
			return fmt.Errorf("%s.path_node_ids must be an array", prefix)
		}
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("%s.id is required", prefix)
		}
		if _, duplicate := actions[record.ID]; duplicate {
			return fmt.Errorf("duplicate action id %q", record.ID)
		}
		if strings.TrimSpace(record.Action) == "" {
			return fmt.Errorf("%s.action is required", prefix)
		}
		if strings.TrimSpace(record.TargetID) == "" {
			return fmt.Errorf("%s.target_id is required", prefix)
		}
		switch record.Status {
		case ActionRunning, ActionSucceeded, ActionFailed, ActionBlocked, ActionSkipped:
		default:
			return fmt.Errorf("%s has unsupported status %q", prefix, record.Status)
		}
		if err := validateExecutionTime(prefix+".started_at", record.StartedAt, true); err != nil {
			return err
		}
		if err := validateExecutionTime(prefix+".completed_at", record.CompletedAt, false); err != nil {
			return err
		}
		if err := validateStringIDs(prefix+".path_node_ids", record.PathNodeIDs); err != nil {
			return err
		}
		actions[record.ID] = record
	}

	recoveries := make(map[string]RecoveryRecord, len(e.Recovery))
	for index, record := range e.Recovery {
		prefix := fmt.Sprintf("recovery[%d]", index)
		if record.CredentialIDs == nil {
			return fmt.Errorf("%s.credential_ids must be an array", prefix)
		}
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("%s.id is required", prefix)
		}
		if _, duplicate := recoveries[record.ID]; duplicate {
			return fmt.Errorf("duplicate recovery id %q", record.ID)
		}
		actionRecord, present := actions[record.ActionID]
		if !present {
			return fmt.Errorf("%s.action_id %q does not reference an action", prefix, record.ActionID)
		}
		if record.Action != actionRecord.Action {
			return fmt.Errorf("%s.action %q does not match action %q", prefix, record.Action, actionRecord.Action)
		}
		switch record.Status {
		case RecoveryPrepared, RecoveryApplied, RecoveryRestored, RecoveryConflict, RecoveryIndeterminate, RecoveryFailed:
		default:
			return fmt.Errorf("%s has unsupported status %q", prefix, record.Status)
		}
		if err := validateExecutionTime(prefix+".prepared_at", record.PreparedAt, true); err != nil {
			return err
		}
		if err := validateExecutionTime(prefix+".updated_at", record.UpdatedAt, true); err != nil {
			return err
		}
		if err := validateStringIDs(prefix+".credential_ids", record.CredentialIDs); err != nil {
			return err
		}
		recoveries[record.ID] = record
	}

	for _, record := range e.Actions {
		if record.RecoveryID == "" {
			continue
		}
		recovery, present := recoveries[record.RecoveryID]
		if !present {
			return fmt.Errorf("action %q recovery_id %q does not reference recovery", record.ID, record.RecoveryID)
		}
		if recovery.ActionID != record.ID {
			return fmt.Errorf("action %q and recovery %q references disagree", record.ID, recovery.ID)
		}
	}
	for _, recovery := range e.Recovery {
		if actionRecord := actions[recovery.ActionID]; actionRecord.RecoveryID != recovery.ID {
			return fmt.Errorf("recovery %q is not referenced by action %q", recovery.ID, recovery.ActionID)
		}
	}

	copy := *e
	copy.RecomputeSummary()
	if !reflect.DeepEqual(e.Summary, copy.Summary) {
		return fmt.Errorf("summary does not match records: got %+v, want %+v", e.Summary, copy.Summary)
	}
	return nil
}

// DecodeScanExecution strictly decodes a meta.extra.scan_execution value.
// Unknown fields and trailing JSON values are rejected.
func DecodeScanExecution(value any) (*ScanExecution, error) {
	var document []byte
	switch value := value.(type) {
	case json.RawMessage:
		document = value
	case []byte:
		document = value
	default:
		var err error
		document, err = json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("encode scan_execution value: %w", err)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var execution ScanExecution
	if err := decoder.Decode(&execution); err != nil {
		return nil, fmt.Errorf("decode scan_execution: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode scan_execution: multiple JSON values are not allowed")
		}
		return nil, fmt.Errorf("decode scan_execution trailing JSON: %w", err)
	}
	if err := execution.Validate(); err != nil {
		return nil, fmt.Errorf("validate scan_execution: %w", err)
	}
	return &execution, nil
}

// GetScanExecution reads and strictly validates meta.extra.scan_execution.
func GetScanExecution(meta IngestMeta) (*ScanExecution, bool, error) {
	value, present := meta.Extra[ScanExecutionExtraKey]
	if !present {
		return nil, false, nil
	}
	execution, err := DecodeScanExecution(value)
	if err != nil {
		return nil, true, err
	}
	return execution, true, nil
}

// SetScanExecution recomputes the summary, validates the record, and stores a
// JSON-compatible value in meta.extra. A nil execution removes the key.
func SetScanExecution(meta *IngestMeta, execution *ScanExecution) error {
	if meta == nil {
		return fmt.Errorf("ingest meta is required")
	}
	if execution == nil {
		delete(meta.Extra, ScanExecutionExtraKey)
		return nil
	}
	execution.normalize()
	execution.RecomputeSummary()
	if err := execution.Validate(); err != nil {
		return fmt.Errorf("validate scan_execution: %w", err)
	}
	document, err := json.Marshal(execution)
	if err != nil {
		return fmt.Errorf("encode scan_execution: %w", err)
	}
	var value any
	if err := json.Unmarshal(document, &value); err != nil {
		return fmt.Errorf("materialize scan_execution: %w", err)
	}
	if meta.Extra == nil {
		meta.Extra = make(map[string]any)
	}
	meta.Extra[ScanExecutionExtraKey] = value
	return nil
}

func (e *ScanExecution) normalize() {
	if e.Exclusions == nil {
		e.Exclusions = []string{}
	}
	if e.Actions == nil {
		e.Actions = []ActionRecord{}
	}
	if e.Recovery == nil {
		e.Recovery = []RecoveryRecord{}
	}
	for index := range e.Actions {
		if e.Actions[index].PathNodeIDs == nil {
			e.Actions[index].PathNodeIDs = []string{}
		}
	}
	for index := range e.Recovery {
		if e.Recovery[index].CredentialIDs == nil {
			e.Recovery[index].CredentialIDs = []string{}
		}
	}
}

func validateExecutionTime(field, value string, required bool) error {
	if value == "" && !required {
		return nil
	}
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("%s is not RFC3339: %w", field, err)
	}
	return nil
}

func validateStringIDs(field string, ids []string) error {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("%s contains an empty ID", field)
		}
		if seen[id] {
			return fmt.Errorf("%s contains duplicate ID %q", field, id)
		}
		seen[id] = true
	}
	return nil
}

func formatExecutionTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

// Journal is the recovery lifecycle surface used by action runners.
type Journal interface {
	Prepare(actionID string, recovery RecoveryRecord) error
	MarkApplied(recoveryID string) error
	MarkRestored(recoveryID string) error
}

// JournalCheckpoint persists the enclosing artifact after a journal update.
type JournalCheckpoint func(*ScanExecution) error

// ScanJournal mutates one ScanExecution and checkpoints every successful
// transition. It intentionally does not create a second receipt file.
type ScanJournal struct {
	mu         sync.Mutex
	execution  *ScanExecution
	checkpoint JournalCheckpoint
	now        func() time.Time
}

func NewJournal(execution *ScanExecution, checkpoint JournalCheckpoint) (*ScanJournal, error) {
	if execution == nil {
		return nil, fmt.Errorf("scan execution is required")
	}
	execution.normalize()
	execution.RecomputeSummary()
	if err := execution.Validate(); err != nil {
		return nil, fmt.Errorf("validate scan execution: %w", err)
	}
	return &ScanJournal{
		execution:  execution,
		checkpoint: checkpoint,
		now:        time.Now,
	}, nil
}

func (j *ScanJournal) Prepare(actionID string, recovery RecoveryRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	actionIndex := j.actionIndex(actionID)
	if actionIndex < 0 {
		return fmt.Errorf("action %q not found", actionID)
	}
	if recovery.ID == "" {
		return fmt.Errorf("recovery id is required")
	}
	if j.recoveryIndex(recovery.ID) >= 0 {
		return fmt.Errorf("recovery %q already exists", recovery.ID)
	}
	actionRecord := &j.execution.Actions[actionIndex]
	if actionRecord.RecoveryID != "" {
		return fmt.Errorf("action %q already references recovery %q", actionID, actionRecord.RecoveryID)
	}
	if recovery.ActionID != "" && recovery.ActionID != actionID {
		return fmt.Errorf("recovery action_id %q does not match %q", recovery.ActionID, actionID)
	}
	if recovery.Action != "" && recovery.Action != actionRecord.Action {
		return fmt.Errorf("recovery action %q does not match %q", recovery.Action, actionRecord.Action)
	}
	if recovery.Status != "" && recovery.Status != RecoveryPrepared {
		return fmt.Errorf("new recovery status = %q, want prepared", recovery.Status)
	}
	stamp := formatExecutionTime(j.now())
	recovery.ActionID = actionID
	recovery.Action = actionRecord.Action
	recovery.Status = RecoveryPrepared
	if recovery.PreparedAt == "" {
		recovery.PreparedAt = stamp
	}
	if recovery.UpdatedAt == "" {
		recovery.UpdatedAt = stamp
	}
	if recovery.CredentialIDs == nil {
		recovery.CredentialIDs = []string{}
	}
	actionRecord.RecoveryID = recovery.ID
	j.execution.Recovery = append(j.execution.Recovery, recovery)
	return j.finishTransition(stamp)
}

func (j *ScanJournal) MarkApplied(recoveryID string) error {
	return j.mark(recoveryID, RecoveryApplied)
}

func (j *ScanJournal) MarkRestored(recoveryID string) error {
	return j.mark(recoveryID, RecoveryRestored)
}

func (j *ScanJournal) mark(recoveryID string, status RecoveryStatus) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	index := j.recoveryIndex(recoveryID)
	if index < 0 {
		return fmt.Errorf("recovery %q not found", recoveryID)
	}
	record := &j.execution.Recovery[index]
	switch status {
	case RecoveryApplied:
		if record.Status != RecoveryPrepared && record.Status != RecoveryApplied {
			return fmt.Errorf("cannot mark recovery %q applied from %q", recoveryID, record.Status)
		}
	case RecoveryRestored:
		if record.Status != RecoveryPrepared && record.Status != RecoveryApplied && record.Status != RecoveryRestored {
			return fmt.Errorf("cannot mark recovery %q restored from %q", recoveryID, record.Status)
		}
	}
	stamp := formatExecutionTime(j.now())
	record.Status = status
	record.UpdatedAt = stamp
	return j.finishTransition(stamp)
}

func (j *ScanJournal) finishTransition(stamp string) error {
	j.execution.UpdatedAt = stamp
	j.execution.normalize()
	j.execution.RecomputeSummary()
	if err := j.execution.Validate(); err != nil {
		return fmt.Errorf("validate journal transition: %w", err)
	}
	if j.checkpoint != nil {
		if err := j.checkpoint(j.execution); err != nil {
			return fmt.Errorf("checkpoint journal transition: %w", err)
		}
	}
	return nil
}

func (j *ScanJournal) actionIndex(id string) int {
	for index := range j.execution.Actions {
		if j.execution.Actions[index].ID == id {
			return index
		}
	}
	return -1
}

func (j *ScanJournal) recoveryIndex(id string) int {
	for index := range j.execution.Recovery {
		if j.execution.Recovery[index].ID == id {
			return index
		}
	}
	return -1
}
