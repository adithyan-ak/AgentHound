# AgentHound PRD — Product Requirements Document

**BloodHound for AI Agent Infrastructure**

Automated graph-based enumeration, trust boundary mapping, and attack path discovery across MCP servers, A2A endpoints, and multi-agent tool chains.

---

## Document Index

| # | Document | Description |
|---|----------|-------------|
| 1 | [Vision & Problem Statement](01-vision.md) | Why this exists, market context, target users, competitive gap |
| 2 | [System Architecture](02-architecture.md) | Tech stack, component design, deployment model, data flow |
| 3 | [Graph Data Model](03-graph-model.md) | Node types, edge types, relationship semantics, schema design |
| 4 | [Collectors](04-collectors.md) | MCP collector, A2A collector, data pipeline, output format |
| 5 | [Attack Path Engine](05-attack-paths.md) | Path algorithms, risk scoring, pre-computed edges, query patterns |
| 6 | [Frontend & Visualization](06-frontend.md) | UI design, graph visualization, reporting, UX flows |
| 7 | [Threat Model Reference](07-threat-model.md) | What AgentHound detects — mapped to OWASP MCP Top 10 and Agentic Top 10 |
| 8 | [MVP Scope & Milestones](08-mvp-scope.md) | MVP definition, phased delivery, acceptance criteria |
| 9 | [Roadmap & Extensibility](09-roadmap.md) | Long-term vision, plugin architecture, business model, academic track |

---

## Key Design Principles

1. **Graph-native thinking.** Every entity is a node, every trust relationship is a directed edge. Attack paths emerge from graph traversal, not heuristics.
2. **Collector-analyzer separation.** Data collection is decoupled from analysis. Collectors produce standardized JSON; the graph engine consumes it. New protocols = new collectors, not new engines.
3. **Edges encode attackability.** Every edge represents a concrete action an attacker could take. Direction follows the flow of access/control. Standard shortest-path algorithms then find attack chains automatically.
4. **Ship the BloodHound way.** Reuse proven architectural patterns from BloodHound CE — dual-database (PostgreSQL + Neo4j), JSON ingest pipeline, post-processed composite edges, Cypher-based pathfinding, Sigma.js visualization.
5. **MCP + A2A from day one.** The MVP supports both protocols. The graph model is protocol-agnostic; collectors are protocol-specific.
6. **Open-source core.** Community adoption drives enterprise value. Apache 2.0 license for the core; commercial features layered on top.

---

## Quick Reference

- **Primary language:** Go (backend, collectors) + TypeScript (frontend)
- **Graph database:** Neo4j (Cypher pathfinding, GDS algorithms)
- **Application database:** PostgreSQL (app data, user management, audit logs)
- **Frontend:** React + Sigma.js + graphology
- **Deployment:** Docker Compose (single `docker compose up`)
- **License:** Apache 2.0
