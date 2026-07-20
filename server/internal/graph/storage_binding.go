package graph

import (
	"context"
	"errors"
	"fmt"

	"github.com/adithyan-ak/agenthound/server/internal/binding"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type StorageBindingInspection struct {
	Marker       *binding.Marker
	ProductEmpty bool
}

type StorageBindingStore struct {
	driver neo4j.DriverWithContext
}

func NewStorageBindingStore(driver neo4j.DriverWithContext) *StorageBindingStore {
	return &StorageBindingStore{driver: driver}
}

func (s *StorageBindingStore) Inspect(
	ctx context.Context,
) (StorageBindingInspection, error) {
	marker, err := s.readOptional(ctx)
	if err != nil {
		return StorageBindingInspection{}, err
	}
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	value, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, `
CALL {
  MATCH (n)
  WHERE NOT n:SchemaVersion AND NOT n:AgentHoundStorageBinding
  RETURN count(n) AS product_nodes
}
CALL {
  MATCH ()-[r]->()
  RETURN count(r) AS product_relationships
}
RETURN product_nodes, product_relationships`, nil)
		if err != nil {
			return nil, err
		}
		if !rows.Next(ctx) {
			if err := rows.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("Neo4j product-state query returned no row")
		}
		nodes, ok := rows.Record().Get("product_nodes")
		if !ok {
			return nil, fmt.Errorf("Neo4j product-state result missing product_nodes")
		}
		relationships, ok := rows.Record().Get("product_relationships")
		if !ok {
			return nil, fmt.Errorf("Neo4j product-state result missing product_relationships")
		}
		nodeCount, ok := nodes.(int64)
		if !ok {
			return nil, fmt.Errorf("Neo4j product_nodes has type %T", nodes)
		}
		relationshipCount, ok := relationships.(int64)
		if !ok {
			return nil, fmt.Errorf("Neo4j product_relationships has type %T", relationships)
		}
		return nodeCount == 0 && relationshipCount == 0, nil
	})
	if err != nil {
		return StorageBindingInspection{}, fmt.Errorf("inspect Neo4j product state: %w", err)
	}
	productEmpty, ok := value.(bool)
	if !ok {
		return StorageBindingInspection{}, fmt.Errorf("unexpected Neo4j product-state type %T", value)
	}
	return StorageBindingInspection{Marker: marker, ProductEmpty: productEmpty}, nil
}

func (s *StorageBindingStore) ReadStorageBinding(
	ctx context.Context,
) (binding.Marker, error) {
	marker, err := s.readOptional(ctx)
	if err != nil {
		return binding.Marker{}, err
	}
	if marker == nil {
		return binding.Marker{}, binding.ErrMarkerMissing
	}
	return *marker, nil
}

func (s *StorageBindingStore) readOptional(
	ctx context.Context,
) (*binding.Marker, error) {
	if s == nil || s.driver == nil {
		return nil, fmt.Errorf("Neo4j storage binding store is unavailable")
	}
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	value, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, `
MATCH (b:AgentHoundStorageBinding)
RETURN b.binding_version AS binding_version,
       b.storage_pair_id AS storage_pair_id,
       b.host_id AS host_id,
       b.network_realm_id AS network_realm_id,
       b.realm_sha256 AS realm_sha256
ORDER BY b.singleton
LIMIT 2`, nil)
		if err != nil {
			return nil, err
		}
		var markers []binding.Marker
		for rows.Next(ctx) {
			record := rows.Record()
			bindingVersion, err := recordInt64(record, "binding_version")
			if err != nil {
				return nil, err
			}
			storagePairID, err := recordString(record, "storage_pair_id")
			if err != nil {
				return nil, err
			}
			hostID, err := recordString(record, "host_id")
			if err != nil {
				return nil, err
			}
			networkRealmID, err := recordString(record, "network_realm_id")
			if err != nil {
				return nil, err
			}
			realmSHA256, err := recordString(record, "realm_sha256")
			if err != nil {
				return nil, err
			}
			markers = append(markers, binding.Marker{
				BindingVersion: int(bindingVersion),
				StoragePairID:  storagePairID,
				HostID:         hostID,
				NetworkRealmID: networkRealmID,
				RealmSHA256:    realmSHA256,
			})
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(markers) > 1 {
			return nil, fmt.Errorf("Neo4j contains multiple storage binding markers")
		}
		if len(markers) == 0 {
			return (*binding.Marker)(nil), nil
		}
		if err := markers[0].Validate(); err != nil {
			return nil, fmt.Errorf("invalid Neo4j storage binding: %w", err)
		}
		return &markers[0], nil
	})
	if err != nil {
		return nil, fmt.Errorf("read Neo4j storage binding: %w", err)
	}
	if value == nil {
		return nil, nil
	}
	marker, ok := value.(*binding.Marker)
	if !ok {
		return nil, fmt.Errorf("unexpected Neo4j storage binding type %T", value)
	}
	return marker, nil
}

func (s *StorageBindingStore) EnsureConstraint(ctx context.Context) error {
	major, _, err := DetectVersion(ctx, s.driver)
	if err != nil {
		return fmt.Errorf("detect Neo4j version for storage binding: %w", err)
	}
	cypher := "CREATE CONSTRAINT unique_agenthoundstoragebinding_singleton ON (b:AgentHoundStorageBinding) ASSERT b.singleton IS UNIQUE"
	if major >= 5 {
		cypher = "CREATE CONSTRAINT unique_agenthoundstoragebinding_singleton IF NOT EXISTS FOR (b:AgentHoundStorageBinding) REQUIRE b.singleton IS UNIQUE"
	}
	if err := runDDL(ctx, s.driver, cypher); err != nil && !isConstraintExistsError(err) {
		return fmt.Errorf("create Neo4j storage binding constraint: %w", err)
	}
	return nil
}

func (s *StorageBindingStore) Install(
	ctx context.Context,
	marker binding.Marker,
) error {
	if err := marker.Validate(); err != nil {
		return fmt.Errorf("install Neo4j storage binding: %w", err)
	}
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, `
MERGE (b:AgentHoundStorageBinding {singleton: 'agenthound'})
ON CREATE SET b.binding_version = $binding_version,
              b.storage_pair_id = $storage_pair_id,
              b.host_id = $host_id,
              b.network_realm_id = $network_realm_id,
              b.realm_sha256 = $realm_sha256,
              b.created_at = datetime()
RETURN b.binding_version AS binding_version`, map[string]any{
			"binding_version":  marker.BindingVersion,
			"storage_pair_id":  marker.StoragePairID,
			"host_id":          marker.HostID,
			"network_realm_id": marker.NetworkRealmID,
			"realm_sha256":     marker.RealmSHA256,
		})
		if err != nil {
			return nil, err
		}
		if !rows.Next(ctx) {
			if err := rows.Err(); err != nil {
				return nil, err
			}
			return nil, errors.New("Neo4j storage binding install returned no row")
		}
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("install Neo4j storage binding: %w", err)
	}
	actual, err := s.ReadStorageBinding(ctx)
	if err != nil {
		return err
	}
	if !actual.Equal(marker) {
		return fmt.Errorf("Neo4j storage binding conflicts with configured immutable tuple")
	}
	return nil
}

func recordString(record *neo4j.Record, key string) (string, error) {
	value, ok := record.Get(key)
	if !ok {
		return "", fmt.Errorf("Neo4j storage binding missing %s", key)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("Neo4j storage binding %s has type %T", key, value)
	}
	return text, nil
}

func recordInt64(record *neo4j.Record, key string) (int64, error) {
	value, ok := record.Get(key)
	if !ok {
		return 0, fmt.Errorf("Neo4j storage binding missing %s", key)
	}
	number, ok := value.(int64)
	if !ok {
		return 0, fmt.Errorf("Neo4j storage binding %s has type %T", key, value)
	}
	return number, nil
}
