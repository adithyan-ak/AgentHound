package appdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/adithyan-ak/agenthound/server/internal/binding"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const storageBindingAdvisoryLockKey int64 = 0x41484f554e44

type StorageInspection struct {
	Marker       *binding.Marker
	ProductEmpty bool
}

type StorageBindingStore struct {
	pool *pgxpool.Pool
}

func NewStorageBindingStore(pool *pgxpool.Pool) *StorageBindingStore {
	return &StorageBindingStore{pool: pool}
}

func AcquireStorageBindingLock(
	ctx context.Context,
	pool *pgxpool.Pool,
) (func(context.Context) error, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire PostgreSQL storage-binding lock connection: %w", err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", storageBindingAdvisoryLockKey); err != nil {
		conn.Release()
		return nil, fmt.Errorf("acquire PostgreSQL storage-binding advisory lock: %w", err)
	}
	released := false
	return func(releaseCtx context.Context) error {
		if released {
			return nil
		}
		released = true
		defer conn.Release()
		var unlocked bool
		if err := conn.QueryRow(
			releaseCtx,
			"SELECT pg_advisory_unlock($1)",
			storageBindingAdvisoryLockKey,
		).Scan(&unlocked); err != nil {
			return fmt.Errorf("release PostgreSQL storage-binding advisory lock: %w", err)
		}
		if !unlocked {
			return fmt.Errorf("PostgreSQL storage-binding advisory lock was not held")
		}
		return nil
	}, nil
}

func (s *StorageBindingStore) Inspect(ctx context.Context) (StorageInspection, error) {
	if s == nil || s.pool == nil {
		return StorageInspection{}, fmt.Errorf("PostgreSQL storage binding store is unavailable")
	}

	markerTable, err := relationExists(ctx, s.pool, "storage_binding")
	if err != nil {
		return StorageInspection{}, err
	}
	var marker *binding.Marker
	if markerTable {
		value, err := s.ReadStorageBinding(ctx)
		switch {
		case err == nil:
			marker = &value
		case errors.Is(err, binding.ErrMarkerMissing):
		default:
			return StorageInspection{}, err
		}
	}

	nonempty, err := postgresProductStateNonempty(ctx, s.pool)
	if err != nil {
		return StorageInspection{}, err
	}
	return StorageInspection{Marker: marker, ProductEmpty: !nonempty}, nil
}

func (s *StorageBindingStore) ReadStorageBinding(ctx context.Context) (binding.Marker, error) {
	if s == nil || s.pool == nil {
		return binding.Marker{}, fmt.Errorf("PostgreSQL storage binding store is unavailable")
	}
	var marker binding.Marker
	err := s.pool.QueryRow(ctx, `
SELECT binding_version, storage_pair_id::text
FROM storage_binding
WHERE singleton = TRUE`).Scan(
		&marker.BindingVersion,
		&marker.StoragePairID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return binding.Marker{}, binding.ErrMarkerMissing
	}
	if err != nil {
		return binding.Marker{}, fmt.Errorf("read PostgreSQL storage binding: %w", err)
	}
	if err := marker.Validate(); err != nil {
		return binding.Marker{}, fmt.Errorf("invalid PostgreSQL storage binding: %w", err)
	}
	return marker, nil
}

func (s *StorageBindingStore) Install(
	ctx context.Context,
	marker binding.Marker,
) error {
	if err := marker.Validate(); err != nil {
		return fmt.Errorf("install PostgreSQL storage binding: %w", err)
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO storage_binding (
  singleton, binding_version, storage_pair_id
) VALUES (TRUE, $1, $2::uuid)
ON CONFLICT (singleton) DO NOTHING`,
		marker.BindingVersion,
		marker.StoragePairID,
	)
	if err != nil {
		return fmt.Errorf("install PostgreSQL storage binding: %w", err)
	}
	actual, err := s.ReadStorageBinding(ctx)
	if err != nil {
		return err
	}
	if !actual.Equal(marker) {
		return fmt.Errorf("PostgreSQL storage binding conflicts with configured immutable tuple")
	}
	return nil
}

func relationExists(ctx context.Context, pool *pgxpool.Pool, name string) (bool, error) {
	var relation *string
	if err := pool.QueryRow(ctx, "SELECT to_regclass($1)::text", name).Scan(&relation); err != nil {
		return false, fmt.Errorf("inspect PostgreSQL relation %s: %w", name, err)
	}
	return relation != nil, nil
}

func postgresProductStateNonempty(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	checks := []struct {
		table string
		query string
	}{
		{"scans", "SELECT EXISTS (SELECT 1 FROM scans)"},
		{"findings", "SELECT EXISTS (SELECT 1 FROM findings)"},
		{"finding_triage", "SELECT EXISTS (SELECT 1 FROM finding_triage)"},
		{"coverage_heads", "SELECT EXISTS (SELECT 1 FROM coverage_heads)"},
		{"coverage_memberships", "SELECT EXISTS (SELECT 1 FROM coverage_memberships)"},
		{"posture_publications", "SELECT EXISTS (SELECT 1 FROM posture_publications)"},
		{"posture_state", `SELECT EXISTS (
SELECT 1 FROM posture_state
WHERE projection_status <> 'unknown'
   OR projection_scan_id IS NOT NULL
   OR projection_error IS NOT NULL
   OR dirty_coverage <> '[]'::jsonb
   OR published_revision IS NOT NULL
   OR published_scan_id IS NOT NULL
   OR published_at IS NOT NULL)`},
	}
	for _, check := range checks {
		exists, err := relationExists(ctx, pool, check.table)
		if err != nil {
			return false, err
		}
		if !exists {
			continue
		}
		var nonempty bool
		if err := pool.QueryRow(ctx, check.query).Scan(&nonempty); err != nil {
			return false, fmt.Errorf("inspect PostgreSQL product table %s: %w", check.table, err)
		}
		if nonempty {
			return true, nil
		}
	}
	return false, nil
}
