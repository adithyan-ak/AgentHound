package appdb

import (
	"context"
	"fmt"
	"time"

	"github.com/adithyan-ak/agenthound/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ScanStore struct {
	pool *pgxpool.Pool
}

func NewScanStore(pool *pgxpool.Pool) *ScanStore {
	return &ScanStore{pool: pool}
}

func (s *ScanStore) CreateScan(ctx context.Context, scan *model.Scan) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO scans (id, collector, status, started_at, metadata)
		 VALUES ($1, $2, $3, $4, $5)`,
		scan.ID, scan.Collector, scan.Status, scan.StartedAt, scan.Metadata)
	if err != nil {
		return fmt.Errorf("create scan: %w", err)
	}
	return nil
}

func (s *ScanStore) UpdateScan(ctx context.Context, id, status string, nodeCount, edgeCount int, scanErr string) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET status = $1, completed_at = $2, node_count = $3, edge_count = $4, error = $5
		 WHERE id = $6`,
		status, now, nodeCount, edgeCount, scanErr, id)
	if err != nil {
		return fmt.Errorf("update scan: %w", err)
	}
	return nil
}

func (s *ScanStore) GetScan(ctx context.Context, id string) (*model.Scan, error) {
	scan := &model.Scan{}
	var scanErr *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, collector, status, started_at, completed_at, node_count, edge_count, error, metadata
		 FROM scans WHERE id = $1`, id).
		Scan(&scan.ID, &scan.Collector, &scan.Status, &scan.StartedAt, &scan.CompletedAt,
			&scan.NodeCount, &scan.EdgeCount, &scanErr, &scan.Metadata)
	if err != nil {
		return nil, fmt.Errorf("get scan: %w", err)
	}
	if scanErr != nil {
		scan.Error = *scanErr
	}
	return scan, nil
}

func (s *ScanStore) ListScans(ctx context.Context, limit, offset int) ([]model.Scan, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, collector, status, started_at, completed_at, node_count, edge_count, error, metadata
		 FROM scans ORDER BY started_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	var scans []model.Scan
	for rows.Next() {
		var s model.Scan
		var scanErr *string
		if err := rows.Scan(&s.ID, &s.Collector, &s.Status, &s.StartedAt, &s.CompletedAt,
			&s.NodeCount, &s.EdgeCount, &scanErr, &s.Metadata); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		if scanErr != nil {
			s.Error = *scanErr
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

func (s *ScanStore) DeleteScan(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scans WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete scan: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("scan not found")
	}
	return nil
}
