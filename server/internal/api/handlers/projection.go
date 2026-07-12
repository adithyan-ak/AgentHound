package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/adithyan-ak/agenthound/server/internal/projection"
)

type projectionStateReader = projection.StateReader
type projectionIdentity = projection.Identity

func guardedProjectionRead[T any](
	ctx context.Context,
	reader projectionStateReader,
	read func() (T, error),
) (T, projectionIdentity, error) {
	return projection.GuardedRead(ctx, reader, read)
}

func writeProjectionConflict(w http.ResponseWriter, err error) bool {
	var conflict *projection.ConflictError
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
