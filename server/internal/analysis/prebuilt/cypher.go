package prebuilt

// All Cypher queries are Neo4j 4.4 compatible (no quantified paths, no pattern comprehensions).

// Critical Paths

// CypherLitellmCredentialLeak surfaces the full v0.2 credential-chain
// finding: an Agent instance whose Config Collector emission has the
// same value_hash as a LiteLLM master-key Credential, and that
// LiteLLM gateway exposes upstream provider keys. The
// cross_service_credential_chain post-processor pre-populates the
// agent → upstream-key CAN_REACH edge; this query joins the path
// for human-readable findings output.
const CypherLitellmCredentialLeak = `
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)-[:HAS_ENV_VAR]->(c1:Credential)
WHERE c1.value_hash IS NOT NULL
MATCH (gw:LiteLLMGateway)-[:EXPOSES_CREDENTIAL]->(c1master:Credential)
WHERE c1master.value_hash = c1.value_hash AND c1master.objectid <> c1.objectid
MATCH (gw)-[:EXPOSES_CREDENTIAL]->(c2:Credential)
WHERE c2.type IN ['apiKey', 'virtual_key']
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

const CypherAgentsShellAccess = `
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
WHERE ANY(cap IN t.capability_surface WHERE cap = 'shell_access')
   OR ANY(cap IN t.capability_surface WHERE cap = 'code_execution')
RETURN a.name AS agent_name,
       s.name AS server_name,
       t.name AS tool_name,
       s.auth_method AS auth_method,
       a.objectid AS agent_id,
       s.objectid AS server_id,
       t.objectid AS tool_id
ORDER BY a.name, s.name, t.name`

const CypherShortestToDatabase = `
MATCH (a:AgentInstance), (r:MCPResource)
WHERE r.uri_scheme IN ['postgres', 'mysql', 'mongodb', 'redis']
MATCH p = shortestPath((a)-[*..10]-(r))
RETURN a.name AS agent_name,
       r.uri AS resource_uri,
       r.sensitivity AS sensitivity,
       length(p) AS path_length,
       [n IN nodes(p) | coalesce(n.name, n.objectid)] AS path_nodes,
       [rel IN relationships(p) | type(rel)] AS path_edges
ORDER BY path_length
LIMIT 50`

const CypherCrossProtocolPaths = `
MATCH (src)-[r:CAN_REACH]->(tgt:MCPResource)
WHERE r.cross_protocol = true
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

const CypherExfiltrationRoutes = `
MATCH (a:AgentInstance)-[exfil:CAN_EXFILTRATE_VIA]->(t:MCPTool)
OPTIONAL MATCH (a)-[reach:CAN_REACH]->(r:MCPResource)
WHERE r.sensitivity IN ['critical', 'high']
RETURN a.name AS agent_name,
       t.name AS exfil_tool,
       exfil.confidence AS exfil_confidence,
       collect(DISTINCT {uri: r.uri, sensitivity: r.sensitivity}) AS sensitive_resources,
       a.objectid AS agent_id,
       t.objectid AS tool_id
ORDER BY exfil.confidence DESC`

const CypherCredentialChain = `
MATCH (a)-[r:CAN_REACH]->(res:MCPResource)
WHERE r.via_credential IS NOT NULL
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

const CypherPoisonedTools = `
MATCH (t:MCPTool)-[r:POISONED_DESCRIPTION]->(t)
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t)
RETURN t.name AS tool_name,
       s.name AS server_name,
       left(t.description, 200) AS description_preview,
       r.evidence AS evidence,
       r.confidence AS confidence,
       t.objectid AS tool_id,
       s.objectid AS server_id
ORDER BY r.confidence DESC`

const CypherToolShadowing = `
MATCH (t1:MCPTool)-[r:SHADOWS]->(t2:MCPTool)
MATCH (s1:MCPServer)-[:PROVIDES_TOOL]->(t1)
MATCH (s2:MCPServer)-[:PROVIDES_TOOL]->(t2)
WHERE s1.objectid <> s2.objectid
RETURN t1.name AS shadowing_tool,
       s1.name AS shadowing_server,
       t2.name AS shadowed_tool,
       s2.name AS shadowed_server,
       r.confidence AS confidence,
       t1.objectid AS shadowing_tool_id,
       t2.objectid AS shadowed_tool_id
ORDER BY r.confidence DESC`

const CypherNoAuthServers = `
MATCH (s:MCPServer)
WHERE s.auth_method = 'none' OR s.auth_method IS NULL
OPTIONAL MATCH (s)-[:PROVIDES_TOOL]->(t:MCPTool)
RETURN s.name AS server_name,
       s.endpoint AS endpoint,
       s.transport AS transport,
       count(t) AS tool_count,
       s.objectid AS server_id
ORDER BY tool_count DESC`

const CypherNoAuthA2A = `
MATCH (a:A2AAgent)
WHERE a.auth_method = 'none' OR a.auth_method IS NULL
OPTIONAL MATCH (a)-[:ADVERTISES_SKILL]->(sk:A2ASkill)
RETURN a.name AS agent_name,
       a.url AS url,
       a.provider AS provider,
       count(sk) AS skill_count,
       a.objectid AS agent_id
ORDER BY skill_count DESC`

const CypherRugPull = `
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
WHERE t.previous_description_hash IS NOT NULL
  AND t.previous_description_hash <> t.description_hash
RETURN t.name AS tool_name,
       s.name AS server_name,
       t.description_hash AS current_hash,
       t.previous_description_hash AS previous_hash,
       t.objectid AS tool_id,
       s.objectid AS server_id
ORDER BY s.name, t.name`

// Supply Chain

const CypherUnpinnedPackages = `
MATCH (s:MCPServer)
WHERE s.is_pinned = false
RETURN s.name AS server_name,
       s.endpoint AS endpoint,
       s.command AS command,
       s.transport AS transport,
       s.objectid AS server_id
ORDER BY s.name`

const CypherInstructionPoisoning = `
MATCH (f:InstructionFile)-[r:POISONED_INSTRUCTIONS]->(f)
OPTIONAL MATCH (a:AgentInstance)-[:LOADS_INSTRUCTIONS]->(f)
RETURN f.path AS file_path,
       f.type AS file_type,
       r.evidence AS evidence,
       r.confidence AS confidence,
       collect(a.name) AS agent_names,
       f.objectid AS file_id
ORDER BY r.confidence DESC`

const CypherUnsignedCards = `
MATCH (a:A2AAgent)
WHERE a.is_signed = false OR a.is_signed IS NULL
RETURN a.name AS agent_name,
       a.url AS url,
       a.provider AS provider,
       a.version AS version,
       a.objectid AS agent_id
ORDER BY a.name`

const CypherHighEntropySecrets = `
MATCH (c:Credential)
WHERE c.high_entropy = true
OPTIONAL MATCH (s:MCPServer)-[:HAS_ENV_VAR]->(c)
RETURN c.name AS credential_name,
       c.type AS credential_type,
       c.source AS source,
       s.name AS server_name,
       c.objectid AS credential_id,
       s.objectid AS server_id
ORDER BY c.name`

// Chokepoints

const CypherChokepointServers = `
MATCH (a:AgentInstance)-[:TRUSTS_SERVER]->(s:MCPServer)
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

const CypherChokepointTools = `
MATCH (t:MCPTool)-[:HAS_ACCESS_TO]->(r:MCPResource)
WITH t, count(r) AS resource_count
WHERE resource_count >= 3
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t)
RETURN t.name AS tool_name,
       s.name AS server_name,
       resource_count,
       t.capability_surface AS capabilities,
       t.objectid AS tool_id,
       s.objectid AS server_id
ORDER BY resource_count DESC`

// Combined

const CypherUnpinnedShell = `
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
WHERE s.is_pinned = false
  AND (ANY(cap IN t.capability_surface WHERE cap = 'shell_access')
       OR ANY(cap IN t.capability_surface WHERE cap = 'code_execution'))
RETURN s.name AS server_name,
       t.name AS tool_name,
       s.command AS command,
       t.capability_surface AS capabilities,
       s.objectid AS server_id,
       t.objectid AS tool_id
ORDER BY s.name, t.name`
