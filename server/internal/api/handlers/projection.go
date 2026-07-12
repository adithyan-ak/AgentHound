package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/adithyan-ak/agenthound/server/model"
)

type projectionStateReader interface {
	GetProjectionState(ctx context.Context) (*model.ProjectionState, error)
}

type projectionIdentity struct {
	ScanID   string `json:"scan_id"`
	Revision int64  `json:"revision"`
}

type projectionConflictError struct {
	Reason string
	State  *model.ProjectionState
	Before *projectionIdentity
	After  *projectionIdentity
}

func (e *projectionConflictError) Error() string {
	if e.Reason == "changed" {
		return fmt.Sprintf("projection changed during read: before=%+v after=%+v", e.Before, e.After)
	}
	return "projection is not readable: " + e.Reason
}

func guardedProjectionRead[T any](
	ctx context.Context,
	reader projectionStateReader,
	read func() (T, error),
) (T, projectionIdentity, error) {
	var zero T
	if reader == nil {
		return zero, projectionIdentity{}, errors.New("projection state reader is unavailable")
	}

	beforeState, err := reader.GetProjectionState(ctx)
	if err != nil {
		return zero, projectionIdentity{}, fmt.Errorf("read projection state before graph read: %w", err)
	}
	before, err := readableProjection(beforeState)
	if err != nil {
		return zero, projectionIdentity{}, err
	}

	value, err := read()
	if err != nil {
		return zero, projectionIdentity{}, err
	}

	afterState, err := reader.GetProjectionState(ctx)
	if err != nil {
		return zero, projectionIdentity{}, fmt.Errorf("read projection state after graph read: %w", err)
	}
	after, err := readableProjection(afterState)
	if err != nil {
		return zero, projectionIdentity{}, err
	}
	if before != after {
		return zero, projectionIdentity{}, &projectionConflictError{
			Reason: "changed",
			Before: &before,
			After:  &after,
		}
	}
	return value, before, nil
}

func readableProjection(state *model.ProjectionState) (projectionIdentity, error) {
	if state == nil {
		return projectionIdentity{}, &projectionConflictError{Reason: "absent"}
	}
	if state.Status != model.ProjectionComplete {
		reason := state.Status
		if reason != model.ProjectionUpdating && reason != model.ProjectionIncomplete {
			reason = "absent"
		}
		return projectionIdentity{}, &projectionConflictError{Reason: reason, State: state}
	}
	if state.ScanID == "" ||
		state.PublishedScanID == "" ||
		state.PublishedRevision == nil ||
		*state.PublishedRevision < 1 {
		return projectionIdentity{}, &projectionConflictError{Reason: "absent", State: state}
	}
	if state.ScanID != state.PublishedScanID {
		return projectionIdentity{}, &projectionConflictError{Reason: "incomplete", State: state}
	}
	if len(state.DirtyCoverage) != 0 {
		return projectionIdentity{}, &projectionConflictError{Reason: "incomplete", State: state}
	}
	return projectionIdentity{
		ScanID:   state.PublishedScanID,
		Revision: *state.PublishedRevision,
	}, nil
}

func writeProjectionConflict(w http.ResponseWriter, err error) bool {
	var conflict *projectionConflictError
	if !errors.As(err, &conflict) {
		return false
	}

	details := map[string]any{"reason": conflict.Reason}
	if conflict.State != nil {
		details["status"] = conflict.State.Status
		details["projection_scan_id"] = conflict.State.ScanID
		details["published_scan_id"] = conflict.State.PublishedScanID
		details["published_revision"] = conflict.State.PublishedRevision
	}
	if conflict.Before != nil {
		details["expected_scan_id"] = conflict.Before.ScanID
		details["expected_revision"] = conflict.Before.Revision
	}
	if conflict.After != nil {
		details["actual_scan_id"] = conflict.After.ScanID
		details["actual_revision"] = conflict.After.Revision
	}
	WriteJSON(w, http.StatusConflict, ErrorResponse{
		Error: ErrorDetail{
			Code:    "PROJECTION_CONFLICT",
			Message: "a stable complete published graph projection is unavailable",
			Details: details,
		},
	})
	return true
}
