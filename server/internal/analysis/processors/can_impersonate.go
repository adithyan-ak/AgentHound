package processors

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/similarity"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

const impersonationThreshold = 0.8

type CanImpersonate struct{}

func (p *CanImpersonate) Name() string           { return "can_impersonate" }
func (p *CanImpersonate) Dependencies() []string { return nil }

func (p *CanImpersonate) Process(ctx context.Context, db graph.GraphDB, scanID string) (graph.ProcessingStats, error) {
	start := time.Now()

	agents, err := p.loadAgents(ctx, db)
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, fmt.Errorf("load agents: %w", err)
	}

	if len(agents) < 2 {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, nil
	}

	docs, err := p.buildDocuments(ctx, db, agents)
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, fmt.Errorf("build documents: %w", err)
	}

	docTexts := make([]string, len(agents))
	for i, a := range agents {
		docTexts[i] = docs[a.id]
	}
	corpus := similarity.NewCorpus(docTexts)

	vectors := make([]map[string]float64, len(agents))
	for i, a := range agents {
		vectors[i] = corpus.TFIDFVector(docs[a.id])
	}

	var edges []ingest.Edge
	now := time.Now().UTC().Format(time.RFC3339)

	for i := 0; i < len(agents); i++ {
		for j := i + 1; j < len(agents); j++ {
			if agents[i].provider != "" && agents[i].provider == agents[j].provider {
				continue
			}
			if vectors[i] == nil || vectors[j] == nil {
				continue
			}

			sim := similarity.CosineSimilarity(vectors[i], vectors[j])
			if sim < impersonationThreshold {
				continue
			}

			edges = append(edges, ingest.Edge{
				Source:     agents[i].id,
				Target:     agents[j].id,
				Kind:       "CAN_IMPERSONATE",
				SourceKind: "A2AAgent",
				TargetKind: "A2AAgent",
				Properties: map[string]any{
					"scan_id":          scanID,
					"last_seen":        now,
					"is_composite":     true,
					"source_collector": "a2a",
					"confidence":       sim,
					"risk_weight":      0.6,
				},
			})

			edges = append(edges, ingest.Edge{
				Source:     agents[j].id,
				Target:     agents[i].id,
				Kind:       "CAN_IMPERSONATE",
				SourceKind: "A2AAgent",
				TargetKind: "A2AAgent",
				Properties: map[string]any{
					"scan_id":          scanID,
					"last_seen":        now,
					"is_composite":     true,
					"source_collector": "a2a",
					"confidence":       sim,
					"risk_weight":      0.6,
				},
			})
		}
	}

	if len(edges) == 0 {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, nil
	}

	written, err := db.WriteEdges(ctx, edges, scanID)
	if err != nil {
		return graph.ProcessingStats{
			ProcessorName: p.Name(),
			Duration:      time.Since(start),
		}, fmt.Errorf("write edges: %w", err)
	}

	return graph.ProcessingStats{
		ProcessorName: p.Name(),
		EdgesCreated:  written,
		Duration:      time.Since(start),
	}, nil
}

type agentInfo struct {
	id       string
	provider string
}

func (p *CanImpersonate) loadAgents(ctx context.Context, db graph.GraphDB) ([]agentInfo, error) {
	rows, err := db.Query(ctx,
		"MATCH (a:A2AAgent) RETURN a.objectid AS id, a.name AS name, a.provider AS provider",
		nil,
	)
	if err != nil {
		return nil, err
	}

	agents := make([]agentInfo, 0, len(rows))
	for _, row := range rows {
		id, _ := row["id"].(string)
		if id == "" {
			continue
		}
		provider, _ := row["provider"].(string)
		agents = append(agents, agentInfo{id: id, provider: provider})
	}
	return agents, nil
}

func (p *CanImpersonate) buildDocuments(ctx context.Context, db graph.GraphDB, agents []agentInfo) (map[string]string, error) {
	docs := make(map[string]string, len(agents))

	for _, a := range agents {
		rows, err := db.Query(ctx,
			"MATCH (a:A2AAgent {objectid: $id})-[:ADVERTISES_SKILL]->(s:A2ASkill) RETURN s.description AS description",
			map[string]any{"id": a.id},
		)
		if err != nil {
			return nil, fmt.Errorf("skills for agent %s: %w", a.id, err)
		}

		var parts []string
		for _, row := range rows {
			desc, _ := row["description"].(string)
			if desc != "" {
				parts = append(parts, desc)
			}
		}
		docs[a.id] = strings.Join(parts, " ")
	}

	return docs, nil
}
