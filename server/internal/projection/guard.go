package projection

import (
	"context"
	"errors"
	"fmt"

	"github.com/adithyan-ak/agenthound/server/model"
)

// StateReader returns the current mutable and published projection state.
type StateReader interface {
	GetProjectionState(ctx context.Context) (*model.ProjectionState, error)
}

// Identity identifies one immutable published graph projection.
type Identity struct {
	ScanID   string `json:"scan_id"`
	Revision int64  `json:"revision"`
}

// ConflictError reports why a stable complete published projection could not
// be used for a graph read.
type ConflictError struct {
	Reason string
	State  *model.ProjectionState
	Before *Identity
	After  *Identity
}

func (e *ConflictError) Error() string {
	if e.Reason == "changed" {
		return fmt.Sprintf(
			"projection changed during read: before=%+v after=%+v",
			e.Before,
			e.After,
		)
	}
	return "projection is not readable: " + e.Reason
}

// GuardedRead executes read only while the published projection is complete
// and stable. It fails closed before the read when no readable publication is
// available, and after the read when publication identity changed.
func GuardedRead[T any](
	ctx context.Context,
	reader StateReader,
	read func() (T, error),
) (T, Identity, error) {
	var zero T
	if reader == nil {
		return zero, Identity{}, errors.New("projection state reader is unavailable")
	}

	beforeState, err := reader.GetProjectionState(ctx)
	if err != nil {
		return zero, Identity{}, fmt.Errorf("read projection state before graph read: %w", err)
	}
	before, err := readable(beforeState)
	if err != nil {
		return zero, Identity{}, err
	}

	value, err := read()
	if err != nil {
		return zero, Identity{}, err
	}

	afterState, err := reader.GetProjectionState(ctx)
	if err != nil {
		return zero, Identity{}, fmt.Errorf("read projection state after graph read: %w", err)
	}
	after, err := readable(afterState)
	if err != nil {
		return zero, Identity{}, err
	}
	if before != after {
		return zero, Identity{}, &ConflictError{
			Reason: "changed",
			Before: &before,
			After:  &after,
		}
	}
	return value, before, nil
}

func readable(state *model.ProjectionState) (Identity, error) {
	if state == nil {
		return Identity{}, &ConflictError{Reason: "absent"}
	}
	if state.Status != model.ProjectionComplete {
		reason := state.Status
		if reason != model.ProjectionUpdating && reason != model.ProjectionIncomplete {
			reason = "absent"
		}
		return Identity{}, &ConflictError{Reason: reason, State: state}
	}
	if state.ScanID == "" ||
		state.PublishedScanID == "" ||
		state.PublishedRevision == nil ||
		*state.PublishedRevision < 1 {
		return Identity{}, &ConflictError{Reason: "absent", State: state}
	}
	if state.ScanID != state.PublishedScanID {
		return Identity{}, &ConflictError{Reason: "incomplete", State: state}
	}
	if len(state.DirtyCoverage) != 0 {
		return Identity{}, &ConflictError{Reason: "incomplete", State: state}
	}
	return Identity{
		ScanID:   state.PublishedScanID,
		Revision: *state.PublishedRevision,
	}, nil
}
