package riskscore

import "context"

type scanScopeKey struct{}

// WithScanScope binds risk-score reads to one immutable scan observation.
func WithScanScope(ctx context.Context, scanID string) context.Context {
	return context.WithValue(ctx, scanScopeKey{}, scanID)
}

func riskParams(ctx context.Context, objectID string) map[string]any {
	scanID, _ := ctx.Value(scanScopeKey{}).(string)
	return map[string]any{"id": objectID, "scan_id": scanID}
}
