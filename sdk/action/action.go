package action

// Action identifies a phase of an engagement. The string values are stable
// identifiers used in CLI flags, registry lookups, and module metadata.
type Action string

const (
	Scan        Action = "scan"
	Fingerprint Action = "fingerprint"
	Enumerate   Action = "enumerate"
	Loot        Action = "loot"
	Extract     Action = "extract"
	Poison      Action = "poison"
	Implant     Action = "implant"
	// Discover is the protocol-discovery action: probe a CIDR for
	// MCP servers (JSON-RPC initialize) and A2A agents (well-known agent
	// cards). Distinct from Scan (TCP port sweep) and Fingerprint
	// (per-host service identity) because the probe semantics are
	// content-driven, not port-driven.
	Discover Action = "discover"
)
