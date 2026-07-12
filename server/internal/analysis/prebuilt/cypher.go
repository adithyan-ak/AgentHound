package prebuilt

// All Cypher queries are Neo4j 4.4 compatible (no quantified paths, no pattern comprehensions).
//
// Generation scoping: every query is scoped to the current logical generations
// via the $gens parameter. Each MANDATORY node anchor carries a
// `ANY(g IN coalesce(x.generations, []) WHERE g IN $gens)` guard so a prebuilt
// analysis never surfaces a retained (demoted) generation's facts. OPTIONAL
// matches used only for supplementary counts are left unguarded so they do not
// become mandatory. The prebuilt handler always supplies $gens and returns an
// empty result set when no generation is promoted, so an unscoped read can
// never leak.

// scopeGen builds the generation-membership predicate for a node OR
// relationship variable. It degrades to unscoped when $gens IS NULL, which is
// how a Postgres-less deployment (no scan store, no promoted generations) runs
// prebuilt queries against the whole graph exactly as before. When $gens is a
// non-empty list the variable must be observed by one of those generations.
func scopeGen(v string) string {
	return "($gens IS NULL OR ANY(g IN coalesce(" + v + ".generations, []) WHERE g IN $gens))"
}

// Critical Paths

// CypherLitellmCredentialLeak surfaces the full credential-chain finding: an
// Agent instance whose Config Collector emission shares a value_hash with a
// LiteLLM master-key Credential, where that gateway exposes upstream provider
// keys. The cross-generation credential chain pre-populates the agent →
// upstream-key CAN_REACH_CREDENTIAL_CHAIN edge; this query joins the path for
// human-readable output, scoped to the current generations.
var CypherLitellmCredentialLeak = `
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)-[:HAS_ENV_VAR]->(c1:Credential)
WHERE c1.value_hash IS NOT NULL
  AND ` + scopeGen("a") + ` AND ` + scopeGen("s") + ` AND ` + scopeGen("c1") + `
MATCH (gw:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->(c1master:Credential)
WHERE c1master.value_hash = c1.value_hash AND c1master.objectid <> c1.objectid
  AND ` + scopeGen("gw") + ` AND ` + scopeGen("c1master") + `
MATCH (gw)-[:EXPOSES_CREDENTIAL]->(c2:Credential)
WHERE c2.type IN ['apiKey', 'virtual_key'] AND ` + scopeGen("c2") + `
RETURN a.name AS agent_name,
       s.name AS via_server,
       c1.name AS via_credential,
       gw.name AS via_gateway,
       gw.endpoint AS gateway_endpoint,
       c2.name AS upstream_credential,
       coalesce(c2.provider, 'unknown') AS upstream_provider,
       a.objectid AS agent_id,
       gw.objectid AS gateway_id,
       c2.objectid AS upstream_credential_id
ORDER BY a.name, gw.name`

var CypherAgentsShellAccess = `
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
WHERE (ANY(cap IN t.capability_surface WHERE cap = 'shell_access')
   OR ANY(cap IN t.capability_surface WHERE cap = 'code_execution'))
  AND ` + scopeGen("a") + ` AND ` + scopeGen("s") + ` AND ` + scopeGen("t") + `
RETURN a.name AS agent_name,
       s.name AS server_name,
       t.name AS tool_name,
       s.auth_method AS auth_method,
       a.objectid AS agent_id,
       s.objectid AS server_id,
       t.objectid AS tool_id
ORDER BY a.name, s.name, t.name`

var CypherShortestToDatabase = `
MATCH (a:AgentInstance), (r:MCPResource)
WHERE r.uri_scheme IN ['postgres', 'mysql', 'mongodb', 'redis']
  AND ` + scopeGen("a") + ` AND ` + scopeGen("r") + `
MATCH p = shortestPath((a)-[*..10]-(r))
WHERE ALL(n IN nodes(p) WHERE ` + scopeGen("n") + `)
  AND ALL(rel IN relationships(p) WHERE ` + scopeGen("rel") + `)
RETURN a.name AS agent_name,
       r.uri AS resource_uri,
       r.sensitivity AS sensitivity,
       length(p) AS path_length,
       [n IN nodes(p) | coalesce(n.name, n.objectid)] AS path_nodes,
       [rel IN relationships(p) | type(rel)] AS path_edges
ORDER BY path_length
LIMIT 50`

var CypherCrossProtocolPaths = `
MATCH (src)-[r:CAN_REACH]->(tgt:MCPResource)
WHERE r.cross_protocol = true
  AND ` + scopeGen("src") + ` AND ` + scopeGen("tgt") + `
  AND ` + scopeGen("r") + `
RETURN src.name AS source_name,
       labels(src)[0] AS source_kind,
       tgt.uri AS target_resource,
       tgt.sensitivity AS sensitivity,
       r.via_host AS via_host,
       r.via_mcp_server AS via_mcp_server,
       r.via_mcp_tool AS via_mcp_tool,
       r.confidence AS confidence,
       src.objectid AS source_id,
       tgt.objectid AS target_id
ORDER BY r.confidence DESC`

var CypherExfiltrationRoutes = `
MATCH (a:AgentInstance)-[exfil:CAN_EXFILTRATE_VIA]->(t:MCPTool)
WHERE ` + scopeGen("a") + ` AND ` + scopeGen("t") + `
  AND ` + scopeGen("exfil") + `
OPTIONAL MATCH (a)-[reach:CAN_REACH]->(r:MCPResource)
WHERE r.sensitivity IN ['critical', 'high']
RETURN a.name AS agent_name,
       t.name AS exfil_tool,
       exfil.confidence AS exfil_confidence,
       collect(DISTINCT {uri: r.uri, sensitivity: r.sensitivity}) AS sensitive_resources,
       a.objectid AS agent_id,
       t.objectid AS tool_id
ORDER BY exfil.confidence DESC`

var CypherCredentialChain = `
MATCH (a)-[r:CAN_REACH]->(res:MCPResource)
WHERE r.via_credential IS NOT NULL
  AND ` + scopeGen("a") + ` AND ` + scopeGen("res") + `
  AND ` + scopeGen("r") + `
RETURN a.name AS agent_name,
       labels(a)[0] AS agent_kind,
       res.uri AS resource_uri,
       res.sensitivity AS sensitivity,
       r.via_credential AS via_credential,
       r.hops AS hops,
       r.confidence AS confidence,
       a.objectid AS agent_id,
       res.objectid AS resource_id
ORDER BY r.hops DESC, r.confidence DESC`

// Vulnerabilities

var CypherPoisonedTools = `
MATCH (t:MCPTool)-[r:POISONED_DESCRIPTION]->(t)
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t)
WHERE ` + scopeGen("t") + ` AND ` + scopeGen("s") + `
RETURN t.name AS tool_name,
       s.name AS server_name,
       left(t.description, 200) AS description_preview,
       r.evidence AS evidence,
       r.confidence AS confidence,
       t.objectid AS tool_id,
       s.objectid AS server_id
ORDER BY r.confidence DESC`

var CypherToolShadowing = `
MATCH (t1:MCPTool)-[r:SHADOWS]->(t2:MCPTool)
MATCH (s1:MCPServer)-[:PROVIDES_TOOL]->(t1)
MATCH (s2:MCPServer)-[:PROVIDES_TOOL]->(t2)
WHERE s1.objectid <> s2.objectid
  AND ` + scopeGen("t1") + ` AND ` + scopeGen("t2") + `
  AND ` + scopeGen("s1") + ` AND ` + scopeGen("s2") + `
RETURN t1.name AS shadowing_tool,
       s1.name AS shadowing_server,
       t2.name AS shadowed_tool,
       s2.name AS shadowed_server,
       r.confidence AS confidence,
       t1.objectid AS shadowing_tool_id,
       t2.objectid AS shadowed_tool_id
ORDER BY r.confidence DESC`

var CypherNoAuthServers = `
MATCH (s:MCPServer)
WHERE (s.auth_method = 'none' OR s.auth_method IS NULL)
  AND ` + scopeGen("s") + `
OPTIONAL MATCH (s)-[:PROVIDES_TOOL]->(t:MCPTool)
RETURN s.name AS server_name,
       s.endpoint AS endpoint,
       s.transport AS transport,
       count(t) AS tool_count,
       s.objectid AS server_id
ORDER BY tool_count DESC`

var CypherNoAuthA2A = `
MATCH (a:A2AAgent)
WHERE (a.auth_method = 'none' OR a.auth_method IS NULL)
  AND ` + scopeGen("a") + `
OPTIONAL MATCH (a)-[:ADVERTISES_SKILL]->(sk:A2ASkill)
RETURN a.name AS agent_name,
       a.url AS url,
       a.provider AS provider,
       count(sk) AS skill_count,
       a.objectid AS agent_id
ORDER BY skill_count DESC`

var CypherRugPull = `
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
WHERE ` + scopeGen("s") + ` AND ` + scopeGen("t") + `
WITH s, t,
  [x IN [
    CASE WHEN t.previous_description_hash IS NOT NULL AND t.previous_description_hash <> t.description_hash THEN 'description' END,
    CASE WHEN t.previous_input_schema_hash IS NOT NULL AND t.previous_input_schema_hash <> t.input_schema_hash THEN 'input_schema' END,
    CASE WHEN s.previous_instructions_hash IS NOT NULL AND s.previous_instructions_hash <> s.instructions_hash THEN 'instructions' END
  ] WHERE x IS NOT NULL] AS changes
WHERE size(changes) > 0
RETURN t.name AS tool_name,
       s.name AS server_name,
       t.description_hash AS current_hash,
       t.previous_description_hash AS previous_hash,
       reduce(acc = '', c IN changes | CASE WHEN acc = '' THEN c ELSE acc + ',' + c END) AS change_kind,
       t.objectid AS tool_id,
       s.objectid AS server_id
ORDER BY s.name, t.name`

// Supply Chain

var CypherUnpinnedPackages = `
MATCH (s:MCPServer)
WHERE s.is_pinned = false
  AND ` + scopeGen("s") + `
RETURN s.name AS server_name,
       s.endpoint AS endpoint,
       s.command AS command,
       s.transport AS transport,
       s.objectid AS server_id
ORDER BY s.name`

var CypherInstructionPoisoning = `
MATCH (f:InstructionFile)-[r:POISONED_INSTRUCTIONS]->(f)
WHERE ` + scopeGen("f") + `
OPTIONAL MATCH (a:AgentInstance)-[:LOADS_INSTRUCTIONS]->(f)
RETURN f.path AS file_path,
       f.type AS file_type,
       r.evidence AS evidence,
       r.confidence AS confidence,
       collect(a.name) AS agent_names,
       f.objectid AS file_id
ORDER BY r.confidence DESC`

var CypherUnsignedCards = `
MATCH (a:A2AAgent)
WHERE (a.is_signed = false OR a.is_signed IS NULL)
  AND ` + scopeGen("a") + `
RETURN a.name AS agent_name,
       a.url AS url,
       a.provider AS provider,
       a.version AS version,
       a.objectid AS agent_id
ORDER BY a.name`

var CypherHighEntropySecrets = `
MATCH (c:Credential)
WHERE c.high_entropy = true
  AND ` + scopeGen("c") + `
OPTIONAL MATCH (s:MCPServer)-[:HAS_ENV_VAR]->(c)
RETURN c.name AS credential_name,
       c.type AS credential_type,
       c.source AS source,
       s.name AS server_name,
       c.objectid AS credential_id,
       s.objectid AS server_id
ORDER BY c.name`

// Chokepoints

var CypherChokepointServers = `
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)
WHERE ` + scopeGen("a") + ` AND ` + scopeGen("s") + `
WITH s, count(a) AS agent_count
WHERE agent_count >= 2
OPTIONAL MATCH (s)-[:PROVIDES_TOOL]->(t:MCPTool)
RETURN s.name AS server_name,
       agent_count,
       count(t) AS tool_count,
       s.auth_method AS auth_method,
       s.endpoint AS endpoint,
       s.objectid AS server_id
ORDER BY agent_count DESC, tool_count DESC`

var CypherChokepointTools = `
MATCH (t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WHERE ` + scopeGen("t") + ` AND ` + scopeGen("r") + `
WITH t, count(r) AS resource_count
WHERE resource_count >= 3
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t)
WHERE ` + scopeGen("s") + `
RETURN t.name AS tool_name,
       s.name AS server_name,
       resource_count,
       t.capability_surface AS capabilities,
       t.objectid AS tool_id,
       s.objectid AS server_id
ORDER BY resource_count DESC`

// Combined

var CypherUnpinnedShell = `
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
WHERE s.is_pinned = false
  AND (ANY(cap IN t.capability_surface WHERE cap = 'shell_access')
       OR ANY(cap IN t.capability_surface WHERE cap = 'code_execution'))
  AND ` + scopeGen("s") + ` AND ` + scopeGen("t") + `
RETURN s.name AS server_name,
       t.name AS tool_name,
       s.command AS command,
       t.capability_surface AS capabilities,
       s.objectid AS server_id,
       t.objectid AS tool_id
ORDER BY s.name, t.name`

// CypherToolNameCollision finds tools on different servers that share a
// normalized (trimmed, lower-cased) name. A collision lets a malicious
// server shadow a trusted tool by registering the same name — the agent may
// invoke the wrong one. Distinct objectids ensure we compare genuinely
// different tools; s1.objectid < s2.objectid deduplicates the (a,b)/(b,a)
// pairing and excludes same-server matches.
var CypherToolNameCollision = `
MATCH (s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool)
MATCH (s2:MCPServer)-[:PROVIDES_TOOL]->(t2:MCPTool)
WHERE s1.objectid < s2.objectid
  AND t1.name IS NOT NULL
  AND t2.name IS NOT NULL
  AND toLower(trim(t1.name)) = toLower(trim(t2.name))
  AND t1.objectid <> t2.objectid
  AND ` + scopeGen("s1") + ` AND ` + scopeGen("s2") + `
  AND ` + scopeGen("t1") + ` AND ` + scopeGen("t2") + `
RETURN t1.name AS tool_name,
       s1.name AS server_a,
       s2.name AS server_b,
       t1.objectid AS tool_a_id,
       t2.objectid AS tool_b_id,
       s1.objectid AS server_a_id,
       s2.objectid AS server_b_id
ORDER BY tool_name`
