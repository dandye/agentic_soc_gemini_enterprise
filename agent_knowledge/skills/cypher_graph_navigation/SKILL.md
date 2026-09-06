---
name: cypher_graph_navigation
description: Heuristics and safe Cypher patterns for operational graph traversal (lateral movement, user logons, credential blast radius, hop limit safety).
---

# Cypher Graph Navigation Skill

This skill provides domain-specific heuristics, query patterns, and safety constraints for traversing the enterprise operational security graph in Neo4j.

## 1. Operational Security Graph Model

The knowledge graph models enterprise entities and relationships across identity, computing assets, network topology, and access privileges:

- **Node Labels**:
  - `User`: Corporate identity, privileged accounts, service accounts (`username`, `name`, `department`, `admin_level`).
  - `Host` / `Computer`: Endpoints, servers, appliances (`hostname`, `name`, `ip`, `os`, `tier`, `role`).
  - `DomainController`: Active Directory domain controllers (`name`, `hostname`, `ip`, `tier="Tier 0"`).
  - `Group`: Security groups, distribution lists, IAM roles (`name`, `gid`, `privilege_tier`).
  - `IPAddress` / `Subnet`: Network locators (`ip`, `cidr`, `zone`).
  - `Process` / `FileHash`: Execution artifacts (`pid`, `name`, `sha256`).

- **Relationship Types**:
  - `LOGGED_IN_TO` / `LOGGED_IN`: User session active on host.
  - `ADMIN_ON` / `CAN_ACCESS`: Administrative or access privileges from User/Group to Host.
  - `MEMBER_OF`: User or Group nested membership.
  - `CONNECTS_TO` / `TRAFFIC_TO`: Observed network communication.
  - `EXECUTED` / `SPAWNED`: Host or User execution of process.
  - `OWNS` / `MANAGES`: Asset ownership relationships.

---

## 2. Core Graph Navigation Heuristics

When investigating security incidents, apply the following traversal strategies based on the investigation phase:

### A. Entity Neighborhood Discovery
- **Objective**: Identify all 1-hop connections (active users, open sessions, group memberships, adjacent hosts) for an initial compromised indicator.
- **Pattern**:
  ```cypher
  MATCH (n)-[r]-(m)
  WHERE n.name = $entity OR n.hostname = $entity OR n.ip = $entity OR n.username = $entity
  RETURN n.name AS source, type(r) AS rel, coalesce(m.name, m.hostname, m.ip, m.username, 'Unknown') AS target, labels(m) AS target_labels
  LIMIT 50
  ```

### B. Lateral Movement Path Analysis
- **Objective**: Detect the shortest attack paths from a compromised entity (e.g. compromised workstation) to high-value targets (Domain Controllers, Tier 0 Crown Jewels).
- **Pattern**:
  ```cypher
  MATCH p = shortestPath((src)-[*1..3]-(dst))
  WHERE (src.name = $entity OR src.hostname = $entity OR src.ip = $entity)
    AND (dst:DomainController OR dst.tier = 'Tier 0' OR dst.role = 'DC')
  RETURN [n in nodes(p) | coalesce(n.name, n.hostname, n.username)] AS path_nodes,
         [r in relationships(p) | type(r)] AS rels,
         length(p) AS hop_count
  LIMIT 10
  ```

### C. Credential Blast Radius Assessment
- **Objective**: Determine all downstream systems and accounts reachable if a specific credential or user account is compromised.
- **Pattern**:
  ```cypher
  MATCH (u:User)-[r:CAN_ACCESS|ADMIN_ON|LOGGED_IN*1..3]->(target)
  WHERE u.name = $entity OR u.username = $entity
  RETURN coalesce(target.name, target.hostname, target.ip) AS accessible_asset,
         labels(target) AS asset_type,
         target.tier AS criticality_tier
  LIMIT 50
  ```

### D. Reverse Pivot (Who Can Access Target?)
- **Objective**: Identify all users and machines capable of administering or pivoting into a compromised high-tier server.
- **Pattern**:
  ```cypher
  MATCH (src)-[r:ADMIN_ON|CAN_ACCESS|MEMBER_OF*1..3]->(dst)
  WHERE dst.name = $entity OR dst.hostname = $entity OR dst.ip = $entity
  RETURN coalesce(src.name, src.username, src.hostname) AS source_entity,
         labels(src) AS source_type,
         type(last(relationships(p))) AS direct_rel
  LIMIT 50
  ```

---

## 3. Safety Constraints & Query Sanitization

To ensure safe, non-destructive execution and protect database performance:

1. **Strictly Read-Only Queries**:
   - Only `MATCH`, `RETURN`, `WHERE`, `WITH`, `UNWIND`, and read-only graph algorithms are allowed.
   - Any query containing destructive mutation keywords (`CREATE`, `DELETE`, `SET`, `REMOVE`, `MERGE`, `DROP`, `DETACH`, `CALL APOC.PERIODIC`) is strictly rejected.

2. **Hop Limit Safety**:
   - Graph traversals must always specify bounded variable-length paths (e.g. `[*1..3]` or `[*1..4]`).
   - Unbounded path queries (`[*]`, `[*..]`, `[*5..]`) cause combinatorial explosion and Cartesian product exhaustion, and are strictly prohibited.
   - Maximum permitted hop limit is clamped to `4` (default recommended is `3`).

3. **Mandatory Result Limits**:
   - Every Cypher traversal must end with an explicit `LIMIT` clause (typically `LIMIT 10` for paths, `LIMIT 50` for neighborhoods).

---

## 4. Integration with `query_knowledge_graph`

When utilizing the `query_knowledge_graph` tool:
- Use `query_type="entity_neighborhood"` for quick 360-degree entity triage.
- Use `query_type="lateral_movement_path"` with `max_hops=3` to trace pivot routes towards Tier 0 infrastructure.
- Use `query_type="credential_blast_radius"` to quantify the blast radius of compromised credentials.
- Use `query_type="raw_cypher"` with validated read-only Cypher for complex investigation-specific graph patterns.
