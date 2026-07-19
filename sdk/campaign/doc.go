// Package campaign holds the collector-safe shared contracts for the
// predicted-to-verified campaign runner: the stable logical Witness exported
// by the server, the differential outcome matrix (Classify), the collector-safe
// evidence transport (Evidence), and the scenario registry.
//
// This package MUST stay linkable from the lean collector binary: it imports
// only the standard library, sdk/common, and sdk/ingest. It never imports
// server/internal, server/model, or the Neo4j driver. In particular it does NOT
// reuse server/model.FindingEvidence (the "observed_signal" evidence state):
// the wire outcome vocabulary here is deliberately independent so a collector
// emission cannot masquerade as a server-assigned finding state.
package campaign
