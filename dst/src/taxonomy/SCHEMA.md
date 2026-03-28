# DST CWE Taxonomy Schema

Each CWE slot is a JSON file in `cwes/cwe-{number}.json`.

## Empty slot (status: "empty")
```json
{
  "id": "CWE-XXX",
  "status": "empty"
}
```

## Filled slot (status: "filled")
```json
{
  "id": "CWE-XXX",
  "name": "Human-readable name from MITRE",
  "status": "filled",
  "description": "What the weakness is, 1-3 sentences",
  "severity": "critical|high|medium|low",
  "category": "injection|authentication|authorization|data_protection|input_output|configuration|reliability|memory|cryptography|file_handling|api|concurrency|error_handling|logging",
  "detection_pattern": "Plain English: what to look for in a Neural Map",
  "graph_query": "DST graph query: source_type→sink_type without mediator",
  "owasp_top10": "A3:2021 or null",
  "sans_top25": true/false,
  "related_cwes": ["CWE-XX", "CWE-YY"],
  "references": ["https://cwe.mitre.org/data/definitions/XXX.html"],
  "filled_by": "agent name",
  "filled_at": "ISO timestamp"
}

## Already implemented in DST (status: "implemented")
Same as filled, plus:
```json
{
  "status": "implemented",
  "implemented_in": ["verifier.ts", "detection-engine.js"],
  "verified_at": "ISO timestamp"
}
```

## Rules for the filling agent
1. Read MITRE page for the CWE
2. Write the detection_pattern in terms of DST's 9 node types: INGRESS, EGRESS, TRANSFORM, CONTROL, AUTH, STORAGE, EXTERNAL, STRUCTURAL, META
3. Write the graph_query as: `source→sink without mediator` format
4. Don't invent — if you can't determine the pattern, set status to "needs_review"
5. One CWE per run. Commit nothing. Just write the JSON file.
