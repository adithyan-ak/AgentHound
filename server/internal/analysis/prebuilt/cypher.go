package prebuilt

// All Cypher queries are Neo4j 4.4 compatible (no quantified paths, no pattern comprehensions).

// Critical Paths

// CypherLitellmCredentialLeak reports the credential exposure that the
// first-party LiteLLM looter can actually observe: an exposed master key.
// Provider apiKey and virtual-key nodes are optional context only when their
// evidence explicitly says the material is masked or hashed and not observed
// as usable plaintext.
const CypherLitellmCredentialLeak = `
MATCH (gw:LiteLLMGateway)-[master_evidence:EXPOSES_CREDENTIAL]->(master:Credential)
WHERE master.type = 'master_key'
  AND master.material_status = 'observed'
  AND master.exposure_status = 'exposed'
  AND master.merge_key = 'value_hash'
  AND master_evidence.exposure_status = 'exposed'
  AND master_evidence.assertion_type = 'observed_credential_exposure'
OPTIONAL MATCH (gw)-[reference_evidence:EXPOSES_CREDENTIAL]->(reference:Credential)
WHERE ((reference.type = 'apiKey' AND reference.material_status = 'masked')
    OR (reference.type = 'virtual_key' AND reference.material_status = 'hashed'))
  AND reference.exposure_status = 'not_observed'
  AND reference_evidence.exposure_status = 'not_observed'
  AND reference_evidence.assertion_type = 'credential_reference'
RETURN gw.name AS gateway_name,
       gw.endpoint AS gateway_endpoint,
       master.name AS master_credential,
       master.material_status AS master_material_status,
       master.exposure_status AS master_exposure_status,
       master_evidence.assertion_type AS master_evidence,
       reference.name AS reference_credential,
       reference.type AS reference_type,
       reference.material_status AS reference_material_status,
       reference.exposure_status AS reference_exposure_status,
       false AS reference_contains_usable_material,
       gw.objectid AS gateway_id,
       master.objectid AS master_credential_id,
       reference.objectid AS reference_credential_id
ORDER BY gw.name, reference.type, reference.name`

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
MATCH p = shortestPath((a)-[:TRUSTS_SERVER|PROVIDES_TOOL|HAS_ACCESS_TO*1..10]->(r))
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
       'hypothesis' AS evidence_state,
       'shared_host' AS correlation,
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
WHERE s.auth_method = 'none'
  AND s.auth_evidence = 'anonymous_probe_succeeded'
OPTIONAL MATCH (s)-[:PROVIDES_TOOL]->(t:MCPTool)
RETURN s.name AS server_name,
       s.endpoint AS endpoint,
       s.transport AS transport,
       count(t) AS tool_count,
       s.objectid AS server_id
ORDER BY tool_count DESC`

const CypherNoAuthA2A = `
MATCH (a:A2AAgent)
WHERE a.auth_method = 'none'
  AND a.auth_evidence = 'anonymous_probe_succeeded'
OPTIONAL MATCH (a)-[:ADVERTISES_SKILL]->(sk:A2ASkill)
RETURN a.name AS agent_name,
       a.url AS url,
       a.provider AS provider,
       count(sk) AS skill_count,
       a.objectid AS agent_id
ORDER BY skill_count DESC`

const CypherRugPull = `
MATCH (s:MCPServer)-[:PROVIDES_TOOL]->(t:MCPTool)
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
WHERE a.signature_verification_status = 'unsigned'
RETURN a.name AS agent_name,
       a.url AS url,
       a.provider AS provider,
       a.version AS version,
       a.objectid AS agent_id
ORDER BY a.name`

const CypherHighEntropySecrets = `
MATCH (c:Credential)
WHERE c.high_entropy = true
  AND c.material_status = 'observed'
  AND c.exposure_status = 'exposed'
  AND c.merge_key = 'value_hash'
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
       s.auth_evidence AS auth_evidence,
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

// CypherToolNameCollision finds tools on different servers that share a
// normalized (trimmed, lower-cased) name. A collision lets a malicious
// server shadow a trusted tool by registering the same name — the agent may
// invoke the wrong one. Distinct objectids ensure we compare genuinely
// different tools; s1.objectid < s2.objectid deduplicates the (a,b)/(b,a)
// pairing and excludes same-server matches.
const CypherToolNameCollision = `
MATCH (s1:MCPServer)-[:PROVIDES_TOOL]->(t1:MCPTool)
MATCH (s2:MCPServer)-[:PROVIDES_TOOL]->(t2:MCPTool)
WHERE s1.objectid < s2.objectid
  AND t1.name IS NOT NULL
  AND t2.name IS NOT NULL
  AND toLower(trim(t1.name)) = toLower(trim(t2.name))
  AND t1.objectid <> t2.objectid
RETURN t1.name AS tool_name,
       s1.name AS server_a,
       s2.name AS server_b,
       t1.objectid AS tool_a_id,
       t2.objectid AS tool_b_id,
       s1.objectid AS server_a_id,
       s2.objectid AS server_b_id
ORDER BY tool_name`
